#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import time
import json
import logging
import subprocess
import shutil
import os
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
from pathlib import Path
import argparse

# ==================== 配置 ====================
class Config:
    CHECK_INTERVAL = 90
    POD_ABNORMAL_THRESHOLD = 300
    LOG_DIR = "/var/log/k8s-pod-reschedule"
    LOG_RETENTION_DAYS = 30
    
    SUPPORTED_WORKLOADS = ["StatefulSet", "Deployment", "ReplicaSet"]
    TAINT_VALUE = "node-role.kubernetes.io/RescuePod=true:NoSchedule"
    
    NAMESPACES: List[str] = []
    EXCLUDE_NAMESPACES = ["kube-system", "kube-public", "kube-node-lease"]
    
    # 监控的异常状态
    MONITORED_REASONS = [
        "NotReady", "Terminating", "Waiting", "Pending", "ContainerCreating",
        "PodInitializing", "Error", "Unknown", "CrashLoopBackOff",
        "ImagePullBackOff", "ErrImagePull", "CreateContainerError",
        "CreateContainerConfigError"
    ]
    
    # Scale 操作等待时间
    SCALE_WAIT_SECONDS = 5

def get_env_config():
    """从环境变量加载配置，环境变量优先级高于命令行参数"""
    env_map = {
        "CHECK_INTERVAL": ("interval", int),
        "POD_ABNORMAL_THRESHOLD": ("threshold", int),
        "LOG_DIR": ("log_dir", str),
        "NAMESPACES": ("namespaces", str),
        "EXCLUDE_NAMESPACES": ("exclude_namespaces", str),
        "SCALE_WAIT_SECONDS": ("scale_wait", int),
    }

    cfg = {}
    for env, (key, cast) in env_map.items():
        val = os.getenv(env)
        if val is not None:
            try:
                cfg[key] = cast(val)
            except Exception:
                    # 字符串类型（namespaces之类）保持原状
                cfg[key] = val
    return cfg

# ==================== 日志 ====================
class LogManager:
    def __init__(self, log_dir: str):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.current_log_date = None
        self.console_buffer = []
        self.console_max_lines = 500
        self.setup_logger()
        
    def setup_logger(self):
        """设置日志记录器"""
        today = datetime.now().strftime('%Y%m%d')
        log_file = self.log_dir / f"reschedule_{today}.log"
        
        formatter = logging.Formatter(
            "%(asctime)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        
        # 文件处理器 - 每天一个文件
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        
        # 控制台处理器 - 使用自定义 Handler 限制行数
        console_handler = LimitedConsoleHandler(self.console_buffer, self.console_max_lines)
        console_handler.setFormatter(formatter)
        
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)
        logger.handlers.clear()
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        self.current_log_date = today
    
    def check_and_rotate_log(self):
        """检查是否需要轮转日志（每天凌晨）"""
        today = datetime.now().strftime('%Y%m%d')
        
        if self.current_log_date != today:
            logging.info("=" * 70)
            logging.info(f"日志轮转: {self.current_log_date} -> {today}")
            logging.info("=" * 70)
            
            # 重新设置日志记录器
            self.setup_logger()
            
            logging.info("=" * 70)
            logging.info(f"新日志文件: reschedule_{today}.log")
            logging.info("=" * 70)
    
    def cleanup_old_logs(self, days: int):
        """清理过期日志"""
        try:
            cutoff = datetime.now() - timedelta(days=days)
            for f in self.log_dir.glob("reschedule_*.log"):
                if datetime.fromtimestamp(f.stat().st_mtime) < cutoff:
                    f.unlink()
                    logging.info(f"删除过期日志: {f.name}")
        except Exception as e:
            logging.error(f"清理日志失败: {e}")


class LimitedConsoleHandler(logging.StreamHandler):
    """限制控制台输出行数的自定义 Handler"""
    
    def __init__(self, buffer: list, max_lines: int):
        super().__init__(sys.stdout)
        self.buffer = buffer
        self.max_lines = max_lines
    
    def emit(self, record):
        """输出日志记录"""
        try:
            msg = self.format(record)
            
            # 添加到缓冲区
            self.buffer.append(msg)
            
            # 保持缓冲区大小
            if len(self.buffer) > self.max_lines:
                self.buffer.pop(0)
            
            # 输出到控制台
            stream = self.stream
            stream.write(msg + self.terminator)
            self.flush()
        except Exception:
            self.handleError(record)

# ==================== K8s 操作 ====================
class K8sOperator:
    def __init__(self):
        self.rescued_nodes: Dict[str, float] = {}
        # 缓存控制器的原始副本数：{kind/namespace/name: replicas}
        self.replica_cache: Dict[str, int] = {}
        self._check_kubectl()
        self._scan_nodes()
    
    def _run(self, cmd: List[str]) -> Tuple[bool, str]:
        """执行命令"""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                  timeout=30, check=False, encoding="utf-8", errors="ignore")
            return result.returncode == 0, result.stdout
        except Exception as e:
            logging.error(f"命令失败: {' '.join(cmd)}: {e}")
            return False, ""
    
    def _check_kubectl(self):
        """检查 kubectl"""
        if not shutil.which("kubectl"):
            logging.error("kubectl 未安装或不在 PATH 中")
            sys.exit(1)
        
        ok, _ = self._run(["kubectl", "get", "nodes", "-o", "name"])
        if not ok:
            logging.error("无法连接到 K8s 集群，请检查 kubeconfig")
            sys.exit(1)
        
        logging.info("✓ kubectl 检查通过")
    
    def _scan_nodes(self):
        """初始扫描节点"""
        logging.info("=" * 70)
        logging.info("初始节点扫描...")
        
        ok, out = self._run(["kubectl", "get", "nodes", "-o", "json"])
        if not ok:
            logging.warning("节点扫描失败")
            return
        
        try:
            nodes = json.loads(out).get("items", [])
        except:
            return
        
        for node in nodes:
            name = node.get("metadata", {}).get("name", "")
            if not name:
                continue
            
            ready = any(c.get("type") == "Ready" and c.get("status") == "True" 
                       for c in node.get("status", {}).get("conditions", []))
            schedulable = not node.get("spec", {}).get("unschedulable", False)
            
            status_str = "[正常]" if ready else "[异常]"
            schedule_str = "[可调度]" if schedulable else "[禁止调度]"
            logging.info(f"节点: {name} - {status_str} - {schedule_str}")
            
            if not ready and schedulable:
                logging.warning(f"→ 发现异常且可调度节点，执行隔离")
                
                if self._cordon_node(name):
                    logging.info(f"✓ 已禁止调度")
                else:
                    logging.warning(f"✗ 禁止调度失败")
                
                if self._add_taint(name):
                    logging.info(f"✓ 已添加 RescuePod 污点")
                    if self._has_rescue_taint(name):
                        logging.info(f"✓ 验证: RescuePod 污点已生效")
                    else:
                        logging.warning(f"⚠ 警告: RescuePod 污点未生效")
                else:
                    logging.warning(f"✗ 添加 RescuePod 污点失败")
                
                self.rescued_nodes[name] = time.time()
        
        logging.info(f"节点扫描完成，救援列表: {len(self.rescued_nodes)} 个节点")
        logging.info("=" * 70)
    
    def get_pods(self) -> List[Dict]:
        """获取 Pod 列表"""
        pods = []
        
        if Config.NAMESPACES:
            for ns in Config.NAMESPACES:
                ok, out = self._run(["kubectl", "get", "pods", "-n", ns, "-o", "json"])
                if ok and out.strip():
                    try:
                        pods.extend(json.loads(out).get("items", []))
                    except:
                        pass
        else:
            ok, out = self._run(["kubectl", "get", "pods", "--all-namespaces", "-o", "json"])
            if ok and out.strip():
                try:
                    pods = json.loads(out).get("items", [])
                except:
                    pass
        
        return [p for p in pods 
                if p.get("metadata", {}).get("namespace") not in Config.EXCLUDE_NAMESPACES]
    
    def _parse_time(self, iso_time: str) -> int:
        """解析时间并返回秒数"""
        try:
            if iso_time.endswith("Z"):
                iso_time = iso_time[:-1] + "+00:00"
            dt = datetime.fromisoformat(iso_time)
            delta = datetime.now(dt.tzinfo) - dt
            return max(0, int(delta.total_seconds()))
        except:
            return 0
    
    def check_pod(self, pod: Dict) -> Tuple[bool, str, int]:
        """检查 Pod 是否异常"""
        meta = pod.get("metadata", {})
        status = pod.get("status", {})
        phase = status.get("phase", "Unknown")
        
        # 检查是否 Terminating
        if meta.get("deletionTimestamp"):
            age = self._parse_time(meta["deletionTimestamp"])
            if age > Config.POD_ABNORMAL_THRESHOLD:
                return True, "Terminating", age
            return False, "", age
        
        age = self._parse_time(meta.get("creationTimestamp", ""))
        if age <= Config.POD_ABNORMAL_THRESHOLD:
            return False, "", age
        
        # 检查 phase 是否在监控列表
        if phase in Config.MONITORED_REASONS:
            return True, phase, age
        
        # 【问题1 修复】检查 Running 但容器未就绪
        if phase == "Running":
            container_statuses = status.get("containerStatuses", [])
            if not container_statuses:
                # 没有容器状态信息，但是 Running，可能异常
                return True, "NotReady", age
            
            for cs in container_statuses:
                if not cs.get("ready", False):
                    # 容器未就绪，检查具体原因
                    state = cs.get("state", {})
                    reason = (state.get("waiting", {}).get("reason") or 
                            state.get("terminated", {}).get("reason") or "NotReady")
                    
                    # 如果原因在监控列表或者就是 NotReady
                    if reason in Config.MONITORED_REASONS or reason == "NotReady":
                        return True, reason, age
        
        return False, "", age
    
    def get_controller(self, pod: Dict) -> Tuple[Optional[str], Optional[str]]:
        """获取控制器"""
        ns = pod.get("metadata", {}).get("namespace", "default")
        owners = pod.get("metadata", {}).get("ownerReferences", [])
        
        for owner in owners:
            kind, name = owner.get("kind"), owner.get("name")
            
            if kind in ["StatefulSet", "Deployment"]:
                return kind, name
            
            if kind == "ReplicaSet":
                ok, out = self._run(["kubectl", "get", "rs", name, "-n", ns, "-o", "json"])
                if ok and out.strip():
                    try:
                        rs = json.loads(out)
                        for rs_owner in rs.get("metadata", {}).get("ownerReferences", []):
                            if rs_owner.get("kind") == "Deployment":
                                return "Deployment", rs_owner.get("name")
                    except:
                        pass
                return "ReplicaSet", name
        
        return None, None
    
    def get_node_status(self, node: str) -> bool:
        """检查节点是否健康"""
        ok, out = self._run(["kubectl", "get", "node", node, "-o", "json"])
        if not ok or not out.strip():
            return False
        
        try:
            data = json.loads(out)
            for c in data.get("status", {}).get("conditions", []):
                if c.get("type") == "Ready":
                    return c.get("status") == "True"
        except:
            pass
        
        return False
    
    def _cordon_node(self, node: str) -> bool:
        """禁止调度"""
        logging.info(f"禁止节点调度: {node}")
        ok, _ = self._run(["kubectl", "cordon", node])
        return ok
    
    def _add_taint(self, node: str) -> bool:
        """添加污点"""
        logging.info(f"添加污点: {node}")
        ok, out = self._run([
            "kubectl", "taint", "nodes", node, 
            Config.TAINT_VALUE, "--overwrite"
        ])
        
        if not ok:
            logging.error(f"添加污点失败，输出: {out}")
        
        return ok
    
    def force_cleanup_node_pods(self, node: str) -> int:
        """强制清理 NotReady 节点上有控制器的 Pod"""
        logging.info(f"强制清理节点 {node} 上的 Pod...")
        
        pods = self.get_pods()
        cleaned = 0
        
        for pod in pods:
            pod_node = pod.get("spec", {}).get("nodeName", "")
            if pod_node != node:
                continue
            
            meta = pod.get("metadata", {})
            name = meta.get("name", "")
            ns = meta.get("namespace", "")
            
            # 检查是否有控制器
            kind, ctrl = self.get_controller(pod)
            
            if kind and ctrl and kind in Config.SUPPORTED_WORKLOADS:
                # 有支持的控制器：强制删除
                logging.info(f"强制删除 Pod: {ns}/{name} (控制器: {kind}/{ctrl})")
                if self.delete_pod(name, ns, force=True):
                    cleaned += 1
            else:
                # 无控制器或不支持：跳过
                if not kind:
                    logging.debug(f"  跳过无控制器 Pod: {ns}/{name}")
                else:
                    logging.debug(f"  跳过不支持的控制器 Pod: {ns}/{name} ({kind})")
        
        if cleaned > 0:
            logging.info(f"✓ 强制清理完成，已删除 {cleaned} 个 Pod")
        else:
            logging.info(f"✓ 节点 {node} 上没有需要清理的 Pod")
        
        return cleaned
    
    def _uncordon_node(self, node: str) -> bool:
        """恢复调度"""
        logging.info(f"恢复节点调度: {node}")
        ok, _ = self._run(["kubectl", "uncordon", node])
        return ok
    
    def _remove_taint(self, node: str) -> bool:
        """移除污点"""
        logging.info(f"移除污点: {node}")
        ok, _ = self._run(["kubectl", "taint", "nodes", node, f"{Config.TAINT_VALUE}-"])
        return ok
    
    def _has_rescue_taint(self, node: str) -> bool:
        """检查是否有救援污点"""
        ok, out = self._run(["kubectl", "get", "node", node, "-o", "json"])
        if not ok or not out.strip():
            return False
        
        try:
            data = json.loads(out)
            taints = data.get("spec", {}).get("taints", [])
            key, rest = Config.TAINT_VALUE.split("=", 1)
            val, eff = rest.split(":", 1)
            
            for t in taints:
                if t.get("key") == key and t.get("value") == val and t.get("effect") == eff:
                    return True
        except:
            pass
        
        return False
    
    def _is_schedulable(self, node: str) -> bool:
        """检查节点是否可调度"""
        ok, out = self._run(["kubectl", "get", "node", node, "-o", "json"])
        if not ok or not out.strip():
            return False
        
        try:
            data = json.loads(out)
            return not data.get("spec", {}).get("unschedulable", False)
        except:
            return False
    
    def _get_current_replicas(self, kind: str, name: str, ns: str) -> Optional[int]:
        """获取当前副本数"""
        resource_map = {
            "Deployment": "deployment",
            "StatefulSet": "statefulset",
            "ReplicaSet": "replicaset"
        }
        
        resource = resource_map.get(kind)
        if not resource:
            return None
        
        ok, out = self._run(["kubectl", "get", resource, name, "-n", ns, "-o", "json"])
        if not ok or not out.strip():
            return None
        
        try:
            data = json.loads(out)
            return data.get("spec", {}).get("replicas", 1)
        except:
            return None
    
    def restart_by_scale(self, kind: str, name: str, ns: str) -> bool:
        """【问题3 修复】统一使用 scale 方式重启"""
        resource_map = {
            "Deployment": "deployment",
            "StatefulSet": "statefulset",
            "ReplicaSet": "replicaset"
        }
        
        resource = resource_map.get(kind)
        if not resource:
            logging.error(f"不支持的资源类型: {kind}")
            return False
        
        # 1. 获取当前副本数
        cache_key = f"{kind}/{ns}/{name}"
        current_replicas = self._get_current_replicas(kind, name, ns)
        
        if current_replicas is None:
            logging.error(f"无法获取 {kind} {ns}/{name} 的副本数")
            return False
        
        # 2. 缓存原始副本数
        self.replica_cache[cache_key] = current_replicas
        logging.info(f"重启 {kind}: {ns}/{name} (副本数: {current_replicas} -> 0 -> {current_replicas})")
        
        # 3. 缩容到 0
        ok, _ = self._run([
            "kubectl", "scale", resource, name, 
            "--replicas=0", "-n", ns
        ])
        
        if not ok:
            logging.error(f"缩容到 0 失败: {kind} {ns}/{name}")
            return False
        
        logging.info(f"✓ 已缩容到 0，等待 {Config.SCALE_WAIT_SECONDS} 秒...")
        time.sleep(Config.SCALE_WAIT_SECONDS)
        
        # 4. 恢复原副本数（优先使用缓存）
        target_replicas = self.replica_cache.get(cache_key, current_replicas)
        ok, _ = self._run([
            "kubectl", "scale", resource, name,
            f"--replicas={target_replicas}", "-n", ns
        ])
        
        if not ok:
            logging.error(f"恢复副本数失败: {kind} {ns}/{name}")
            return False
        
        logging.info(f"✓ 已恢复副本数到 {target_replicas}")
        return True
    
    def delete_pod(self, name: str, ns: str, force: bool = False) -> bool:
        """删除 Pod（仅用于 Terminating 场景）"""
        cmd = ["kubectl", "delete", "pod", name, "-n", ns]
        if force:
            logging.info(f"✓ 强制删除 Pod: {ns}/{name}")
            cmd.extend(["--force", "--grace-period=0"])
        else:
            logging.info(f"✓ 删除 Pod: {ns}/{name}")
        
        ok, _ = self._run(cmd)
        return ok
    
    def check_all_nodes(self) -> List[str]:
        """检查所有节点，发现需要处理的异常节点"""
        ok, out = self._run(["kubectl", "get", "nodes", "-o", "json"])
        if not ok or not out.strip():
            return []
        
        try:
            nodes = json.loads(out).get("items", [])
        except:
            return []
        
        newly_isolated_nodes = []
        
        # 统计可用节点数量
        ready_schedulable_count = 0
        for node in nodes:
            name = node.get("metadata", {}).get("name", "")
            if not name:
                continue
            
            ready = any(c.get("type") == "Ready" and c.get("status") == "True" 
                       for c in node.get("status", {}).get("conditions", []))
            schedulable = not node.get("spec", {}).get("unschedulable", False)
            
            if ready and schedulable:
                ready_schedulable_count += 1
        
        # 处理每个节点
        for node in nodes:
            name = node.get("metadata", {}).get("name", "")
            if not name:
                continue
            
            ready = any(c.get("type") == "Ready" and c.get("status") == "True" 
                       for c in node.get("status", {}).get("conditions", []))
            schedulable = not node.get("spec", {}).get("unschedulable", False)
            has_rescue = self._has_rescue_taint(name)
            
            # 场景1：NotReady + 可调度 + 无 RescuePod 污点 → 需要隔离
            if not ready and schedulable and not has_rescue:
                logging.warning("=" * 70)
                logging.warning(f"⚠ 检测到异常节点: {name} (NotReady + 可调度 + 无 RescuePod 污点)")
                
                # 隔离节点
                if self._cordon_node(name):
                    logging.info(f"✓ 已禁止节点 {name} 调度")
                else:
                    logging.warning(f"✗ 禁止节点 {name} 调度失败")
                
                if self._add_taint(name):
                    logging.info(f"✓ 已为节点 {name} 添加 RescuePod 污点")
                else:
                    logging.warning(f"✗ 为节点 {name} 添加污点失败")
                
                self.rescued_nodes[name] = time.time()
                newly_isolated_nodes.append(name)
                
                # 如果有可用节点，强制清理 Pod
                if ready_schedulable_count > 0:
                    logging.info(f"检测到 {ready_schedulable_count} 个可用节点，开始强制清理...")
                    self.force_cleanup_node_pods(name)
                else:
                    logging.error(f"⚠ 警告：没有可用节点，跳过 Pod 清理（避免服务全部中断）")
                
                logging.warning("=" * 70)
            
            # 场景2：NotReady + 禁止调度 + 有 RescuePod 污点 → 已处理，但可能需要清理残留 Pod
            elif not ready and not schedulable and has_rescue:
                if name not in self.rescued_nodes:
                    self.rescued_nodes[name] = time.time()
                    logging.info(f"发现已隔离节点（可能为程序重启前处理）: {name}")
                    
                    # 检查是否有残留 Pod 需要清理
                    if ready_schedulable_count > 0:
                        cleaned = self.force_cleanup_node_pods(name)
                        if cleaned > 0:
                            logging.info(f"清理了 {cleaned} 个残留 Pod")
            
            # 场景3：Ready + 禁止调度 + 有 RescuePod 污点 → 需要恢复
            elif ready and not schedulable and has_rescue:
                if name not in self.rescued_nodes:
                    self.rescued_nodes[name] = time.time()
                    logging.info(f"发现需要恢复的节点: {name}")
        
        return newly_isolated_nodes

# ==================== 主控制器 ====================
class PodRescheduler:
    def __init__(self):
        self.k8s = K8sOperator()
        self.processed: Dict[str, float] = {}
    
    def handle_pod(self, pod: Dict, reason: str, age: int):
        """处理异常 Pod"""
        meta = pod.get("metadata", {})
        name = meta.get("name", "")
        ns = meta.get("namespace", "")
        node = pod.get("spec", {}).get("nodeName", "")
        
        key = f"{ns}/{name}"
        if key in self.processed and time.time() - self.processed[key] < 600:
            return
        
        logging.warning("=" * 70)
        logging.warning(f"异常 Pod: {key}")
        logging.warning(f"节点: {node or 'Unscheduled'}")
        logging.warning(f"原因: {reason}")
        logging.warning(f"时长: {age}s")
        
        kind, ctrl = self.k8s.get_controller(pod)
        if not kind or not ctrl:
            logging.warning("  无控制器，跳过")
            logging.warning("=" * 70)
            return
        
        logging.info(f"控制器: {kind}/{ctrl}")
        
        is_terminating = reason == "Terminating"
        
        # 未调度
        if not node:
            logging.info("  未调度到节点")
            ok = self._reschedule(kind, ctrl, ns, name, False, is_terminating)
            if ok:
                logging.info("✓ 重调度成功")
                self.processed[key] = time.time()
            else:
                logging.error("✗ 重调度失败")
            logging.warning("=" * 70)
            return
        
        # 已调度：检查节点
        node_ok = self.k8s.get_node_status(node)
        logging.info(f"节点状态: {'正常' if node_ok else '异常'}")
        
        # 节点异常且可调度：隔离
        if not node_ok:
            if self.k8s._is_schedulable(node) and not self.k8s._has_rescue_taint(node):
                logging.warning(f"隔离节点 {node}")
                
                if self.k8s._cordon_node(node):
                    logging.info(f"✓ 已禁止调度")
                else:
                    logging.warning(f"✗ 禁止调度失败")
                
                if self.k8s._add_taint(node):
                    logging.info(f"✓ 已添加 RescuePod 污点")
                else:
                    logging.warning(f"✗ 添加 RescuePod 污点失败")
                
                self.k8s.rescued_nodes[node] = time.time()
            elif not self.k8s._is_schedulable(node):
                logging.info(f"节点 {node} 已禁止调度，跳过 cordon")
            elif self.k8s._has_rescue_taint(node):
                logging.info(f"节点 {node} 已有 RescuePod 污点，跳过")
        
        # 重调度
        ok = self._reschedule(kind, ctrl, ns, name, not node_ok, is_terminating)
        if ok:
            logging.info("✓ 重调度成功")
            self.processed[key] = time.time()
        else:
            logging.error("✗ 重调度失败")
        
        logging.warning("=" * 70)
    
    def _reschedule(self, kind: str, ctrl: str, ns: str, pod: str, 
                    node_bad: bool, terminating: bool) -> bool:
        """执行重调度"""
        # Terminating 超时：强制删除
        if terminating:
            return self.k8s.delete_pod(pod, ns, force=True)
        
        # 其他情况：统一使用 scale 0 方式
        return self.k8s.restart_by_scale(kind, ctrl, ns)
    
    def recover_nodes(self):
        """【问题2 修复】恢复已救援的节点"""
        if not self.k8s.rescued_nodes:
            return
        
        logging.info("=" * 70)
        logging.info("检查已救援节点...")
        to_remove = []
        
        for node, rescue_time in list(self.k8s.rescued_nodes.items()):
            node_ok = self.k8s.get_node_status(node)
            elapsed = int(time.time() - rescue_time)
            
            logging.info(f"节点: {node}")
            logging.info(f"状态: {'正常' if node_ok else '异常'}")
            logging.info(f"救援时长: {elapsed}s")
            
            if not node_ok:
                if elapsed > 1800:
                    logging.error(f"⚠ 异常超过 30 分钟")
                continue
            
            # 节点已恢复：检查是否有 RescuePod 污点
            has_rescue = self.k8s._has_rescue_taint(node)
            
            if has_rescue:
                # 有救援污点：先移除污点，再 uncordon
                logging.info(f"检测到 RescuePod 污点，执行恢复...")
                
                if self.k8s._remove_taint(node):
                    logging.info(f"✓ 已移除污点")
                else:
                    logging.warning(f"✗ 移除污点失败")
                    continue
                
                # 污点移除成功后，再检查是否需要 uncordon
                if not self.k8s._is_schedulable(node):
                    if self.k8s._uncordon_node(node):
                        logging.info(f"✓ 已恢复调度")
                    else:
                        logging.warning(f"✗ 恢复调度失败")
                        continue
                else:
                    logging.info(f"节点已可调度")
                
                to_remove.append(node)
                logging.info(f"✓ 节点恢复完成")
            else:
                # 没有救援污点：可能是人工操作，不处理
                logging.warning(f"未检测到 RescuePod 污点")
                
                if not self.k8s._is_schedulable(node):
                    logging.warning(f"节点禁止调度可能为人工设置，保持现状")
                else:
                    logging.info(f"节点已可调度，标记为已恢复")
                    to_remove.append(node)
        
        for node in to_remove:
            self.k8s.rescued_nodes.pop(node, None)
        
        if to_remove:
            logging.info(f"本轮恢复节点数: {len(to_remove)}")
        
        logging.info("=" * 70)
    
    def run(self):
        """主循环"""
        logging.info("=" * 70)
        logging.info("Pod 自动重调度服务启动")
        logging.info(f"检查间隔: {Config.CHECK_INTERVAL}s")
        logging.info(f"异常阈值: {Config.POD_ABNORMAL_THRESHOLD}s")
        logging.info(f"监控状态: {', '.join(Config.MONITORED_REASONS[:5])} ...")
        logging.info(f"重启方式: 统一使用 scale 0 -> 原副本数")
        logging.info("=" * 70)
        
        while True:
            try:
                # 1. 主动检查节点健康状态（优先级最高）
                newly_isolated = self.k8s.check_all_nodes()
                if newly_isolated:
                    logging.warning(f"本轮新隔离节点: {', '.join(newly_isolated)}")
                
                # 2. 恢复节点
                self.recover_nodes()
                
                # 3. 检查 Pod
                pods = self.k8s.get_pods()
                logging.info(f"监控 Pod 数: {len(pods)}")
                
                abnormal = 0
                for pod in pods:
                    is_bad, reason, age = self.k8s.check_pod(pod)
                    if is_bad:
                        abnormal += 1
                        self.handle_pod(pod, reason, age)
                
                if abnormal == 0:
                    logging.info("所有 Pod 正常")
                    
                    # 【优化1】所有 Pod 正常时，清理所有缓存
                    if self.processed or self.k8s.replica_cache:
                        logging.info("清理所有缓存（Pod 全部正常）")
                        self.processed.clear()
                        self.k8s.replica_cache.clear()
                else:
                    logging.info(f"异常 Pod 数: {abnormal}")
                    
                    # 有异常时，清理过期记录
                    now = time.time()
                    self.processed = {k: v for k, v in self.processed.items() if now - v < 3600}
                    
                    # 清理过期副本缓存（保留最近 500 条）
                    if len(self.k8s.replica_cache) > 1000:
                        cache_items = list(self.k8s.replica_cache.items())
                        self.k8s.replica_cache = dict(cache_items[-500:])
                        logging.info("清理副本缓存（超过 1000 条）")
                
                logging.info(f"等待 {Config.CHECK_INTERVAL}s...\n")
                time.sleep(Config.CHECK_INTERVAL)
                
            except KeyboardInterrupt:
                logging.info("收到退出信号")
                break
            except Exception as e:
                logging.error(f"运行异常: {e}", exc_info=True)
                time.sleep(Config.CHECK_INTERVAL)

# ==================== 主程序 ====================
def main():
    parser = argparse.ArgumentParser(description="K8s Pod 异常自动重调度")
    parser.add_argument("--interval", type=int, default=90, help="检查间隔（秒）")
    parser.add_argument("--threshold", type=int, default=300, help="异常阈值（秒）")
    parser.add_argument("--log-dir", type=str, default="/var/log/k8s-pod-reschedule", help="日志目录")
    parser.add_argument("--namespaces", type=str, help="监控命名空间（逗号分隔）")
    parser.add_argument("--exclude-namespaces", type=str, help="排除命名空间（逗号分隔）")
    parser.add_argument("--scale-wait", type=int, default=5, help="Scale 操作等待时间（秒）")
    
    args = parser.parse_args()

    # 读取环境变量（覆盖上述 args）
    env_cfg = get_env_config()
    for k, v in env_cfg.items():
        setattr(args, k, v)

    # 应用配置
    Config.CHECK_INTERVAL = args.interval
    Config.POD_ABNORMAL_THRESHOLD = args.threshold
    Config.LOG_DIR = args.log_dir
    Config.SCALE_WAIT_SECONDS = args.scale_wait

    if args.namespaces:
        Config.NAMESPACES = [n.strip() for n in args.namespaces.split(",") if n.strip()]

    if args.exclude_namespaces:
        Config.EXCLUDE_NAMESPACES.extend(
            [n.strip() for n in args.exclude_namespaces.split(",") if n.strip()]
        )

    log_mgr = LogManager(Config.LOG_DIR)
    log_mgr.cleanup_old_logs(Config.LOG_RETENTION_DAYS)
    
    rescheduler = PodRescheduler()
    rescheduler.run()

if __name__ == "__main__":
    main()
