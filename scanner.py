import argparse
import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
COMMON_PORTS = {
    21: "FTP — 文件传输协议，明文传账号密码，现已少用",
    22: "SSH — 加密远程登录，管理 Linux 服务器的标准方式",
    23: "Telnet — 老式远程登录，全程明文，已基本被 SSH 取代",
    25: "SMTP — 发送邮件",
    53: "DNS — 域名解析",
    80: "HTTP — 网页服务，明文传输",
    110: "POP3 — 接收邮件（明文）",
    135: "RPC — Windows 远程过程调用的端点映射服务",
    139: "NetBIOS — Windows 文件共享相关的会话服务",
    143: "IMAP — 接收并在服务器上管理邮件",
    389: "LDAP — 目录服务，域环境里用来查账号和组织信息",
    443: "HTTPS — 加密的网页服务",
    445: "SMB — Windows 文件共享，永恒之蓝等高危漏洞就出在这里",
    465: "SMTPS — 加密发送邮件",
    993: "IMAPS — 加密接收邮件",
    995: "POP3S — 加密接收邮件",
    1080: "SOCKS — 通用代理协议的常用端口",
    1433: "SQL Server — 微软的数据库服务",
    1521: "Oracle — Oracle 数据库的监听端口",
    2375: "Docker API — 未授权访问可直接控制容器和主机，高危",
    3306: "MySQL — 最常见的开源数据库之一",
    3389: "RDP — Windows 远程桌面，常被口令爆破盯上",
    5432: "PostgreSQL — 开源数据库",
    5900: "VNC — 图形化远程桌面",
    6379: "Redis — 内存数据库/缓存，未授权访问是经典入侵入口",
    8000: "HTTP 备用 — 开发调试和临时 Web 服务常用",
    8080: "HTTP 备用/代理 — Web 备用端口或代理服务常用",
    8443: "HTTPS 备用 — 备用的加密网页服务",
    9200: "Elasticsearch — 搜索服务，未授权访问曾造成大量数据泄露",
    11211: "Memcached — 内存缓存服务",
    27017: "MongoDB — 文档型数据库",
}
def check_port(ip, port, timeout=1):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        result = s.connect_ex((ip, port))
        if result == 0:
            return port
        return None
    except OSError as e:
        print(f"{ip}:{port} 抛异常 {type(e).__name__}: {e}")
        return None
    finally:
        s.close()

def scan_ports_sequential(ip, ports, timeout=1):
    open_ports = []
    for port in ports:
        result = check_port(ip, port, timeout)
        if result is not None:
            open_ports.append(result)
    return sorted(open_ports)

def scan_ports(ip, ports, timeout=1, max_workers=50):
    ports = list(ports)  # range 转成 list，方便重复使用
    open_ports = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(check_port, ip, port, timeout) for port in ports]
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                open_ports.append(result)
    return sorted(open_ports)

# ---------- 输入校验：给 argparse 用的类型检查函数 ----------

def valid_port(value):
    """端口必须是 1-65535 之间的整数，不合格 argparse 会直接报错退出。"""
    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"端口必须是整数，你输入的是: {value!r}")
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError(f"端口必须在 1-65535 之间，你输入的是: {port}")
    return port

def valid_timeout(value):
    try:
        timeout = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"超时必须是数字，你输入的是: {value!r}")
    if not 0 < timeout <= 30:
        raise argparse.ArgumentTypeError(f"超时必须在 (0, 30] 秒之间，你输入的是: {timeout}")
    return timeout

def valid_workers(value):
    try:
        workers = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"线程数必须是整数，你输入的是: {value!r}")
    if not 1 <= workers <= 200:
        raise argparse.ArgumentTypeError(f"线程数必须在 1-200 之间，你输入的是: {workers}")
    return workers

def resolve_target(parser, target):
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        ip = None
    if ip is not None:
        if ip.version == 6:
            parser.error(f"暂只支持 IPv4，不支持 IPv6 地址: {target!r}")
        return str(ip)
    try:
        return socket.gethostbyname(target)  # 不是 IP，就试试能不能当主机名解析
    except OSError:
        parser.error(f"目标无效或无法解析: {target!r}（请输入合法 IP 或主机名）")

# ---------- 命令行入口 ----------
def build_parser():
    parser = argparse.ArgumentParser(description="TCP 端口扫描器（多线程）")
    parser.add_argument("target", help="目标 IP 或主机名，如 127.0.0.1")
    parser.add_argument("start_port", nargs="?", type=valid_port, default=1,
                        help="起始端口，默认 1")
    parser.add_argument("end_port", nargs="?", type=valid_port, default=1024,
                        help="结束端口，默认 1024")
    parser.add_argument("-t", "--timeout", type=valid_timeout, default=1.0,
                        help="每个端口的连接超时（秒），默认 1")
    parser.add_argument("-w", "--workers", type=valid_workers, default=50,
                        help="并发线程数，默认 50")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--sequential", action="store_true",
                       help="单线程顺序扫描（用于和并发版对比耗时）")
    group.add_argument("--benchmark", action="store_true",
                       help="顺序和并发各扫一遍，打印耗时对比")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # argparse 管单个值的合法性，下面两条跨字段的规则在这里补检
    target_ip = resolve_target(parser, args.target)
    if target_ip != args.target:
        print(f"目标 {args.target} 解析为 {target_ip}")
    if args.start_port > args.end_port:
        parser.error(f"起始端口({args.start_port}) 不能大于结束端口({args.end_port})")
    ports = range(args.start_port, args.end_port + 1)  # range 左闭右开，要 +1

    if args.benchmark:
        print(f"基准对比: {target_ip} 的 {args.start_port}-{args.end_port} 端口，超时 {args.timeout}s")
        start = time.perf_counter()
        seq_result = scan_ports_sequential(target_ip, ports, args.timeout)
        seq_time = time.perf_counter() - start
        print(f"顺序扫描（单线程）: {seq_time:.3f} 秒，开放端口: {seq_result if seq_result else '无'}")

        start = time.perf_counter()
        con_result = scan_ports(target_ip, ports, args.timeout, args.workers)
        con_time = time.perf_counter() - start
        print(f"并发扫描（{args.workers} 线程）: {con_time:.3f} 秒，开放端口: {con_result if con_result else '无'}")

        if seq_result == con_result:
            print("两次结果一致 ✓")
        if con_time > 0 and seq_time > con_time:
            print(f"并发提速约 {seq_time / con_time:.1f} 倍")
        elif con_time > 0:
            print("这次并发没有更快：目标响应太快时（比如本机 127.0.0.1，关闭端口立刻拒绝），"
                  "单次连接几乎不等待，线程创建和调度的开销反而占了大头。"
                  "扫响应慢或有端口被防火墙丢弃的目标时，并发才会明显提速。")
        return

    mode = "单线程" if args.sequential else f"{args.workers} 线程并发"
    print(f"正在扫描 {target_ip} 的 {args.start_port}-{args.end_port} 端口（{mode}，超时 {args.timeout}s）...")
    start = time.perf_counter()
    if args.sequential:
        open_list = scan_ports_sequential(target_ip, ports, args.timeout)
    else:
        open_list = scan_ports(target_ip, ports, args.timeout, args.workers)
    elapsed = time.perf_counter() - start

    for port in open_list:
       info = COMMON_PORTS.get(port)
       if info:
           print(f"Port {port}: Open — {info}")
       else:
           print(f"Port {port}: Open")
    print(f"\n扫描完成，用时 {elapsed:.3f} 秒，开放端口: {open_list if open_list else '无'}")

if __name__ == "__main__":
    main()



