"""
CLI Testing Script for Backend Scanner

WHY THIS FILE EXISTS:
    Allows running and testing domain/IP scans directly from the terminal 
    without needing to launch a Uvicorn HTTP server.

USAGE:
    python test_domain.py example.com
    python test_domain.py 8.8.8.8
"""
import argparse
import asyncio
import json
import sys

from common.database import AsyncSessionLocal, close_db, init_db
from modules.domain.service import DomainService


async def main():
    parser = argparse.ArgumentParser(description="Test Backend Domain Scanner directly from Terminal")
    parser.add_argument("target", help="Domain name or IP to scan (e.g. google.com or 8.8.8.8)")
    parser.add_argument("--max-subdomains", type=int, default=50, help="Maximum subdomains to list in terminal (default: 50)")
    args = parser.parse_args()

    print(f"\n==========================================")
    print(f"  STARTING BACKEND SCAN: {args.target}")
    print(f"==========================================\n")

    await init_db()
    service = DomainService()

    try:
        async with AsyncSessionLocal() as session:
            report = await service.run_scan(args.target, session)

            print("\n==========================================")
            print("         SCAN COMPLETED SUCCESSFULLY      ")
            print("==========================================")
            print(f"Scan ID     : {report.get('scan_id')}")
            print(f"Target      : {report.get('target_domain')}")
            print(f"Duration    : {report.get('duration_seconds')} seconds")
            print(f"Total Assets: {report.get('total_assets_found')}")
            
            attack_surface = report.get("attack_surface", {})
            print(f"\n--- ATTACK SURFACE RISK ASSESSMENT ---")
            print(f"Risk Score  : {attack_surface.get('risk_score')} / 100")
            print(f"Severity    : {attack_surface.get('severity', '').upper()}")
            
            print("\n--- KEY FINDINGS ---")
            findings = attack_surface.get("key_findings", [])
            if findings:
                for f in findings:
                    print(f"  • {f}")
            else:
                print("  None")

            # ── DETAILED DISCOVERED ASSETS DISPLAY ──────────────────────
            assets = report.get("assets", {})

            # 1. Subdomains
            subdomains = [a.get("asset_value") for a in assets.get("subdomain", []) if a.get("asset_value")]
            print(f"\n--- DISCOVERED SUBDOMAINS ({len(subdomains)}) ---")
            if subdomains:
                limit = args.max_subdomains
                for sub in subdomains[:limit]:
                    print(f"  [+] {sub}")
                if len(subdomains) > limit:
                    print(f"  ... and {len(subdomains) - limit} more subdomains (see last_scan_report.json)")
            else:
                print("  None found")

            # 2. IP Addresses
            ips = [a.get("asset_value") for a in assets.get("ip_address", []) if a.get("asset_value")]
            print(f"\n--- DISCOVERED IP ADDRESSES ({len(ips)}) ---")
            if ips:
                for ip in ips:
                    print(f"  [+] {ip}")
            else:
                print("  None found")

            # 3. Open Ports & Services
            open_ports = assets.get("open_port", [])
            services = assets.get("service", [])
            print(f"\n--- OPEN PORTS & SERVICES ({len(open_ports)}) ---")
            if open_ports:
                for port in open_ports:
                    raw = port.get("raw_data", {})
                    port_num = raw.get("port") or port.get("asset_value")
                    service_name = raw.get("service", "unknown")
                    banner = raw.get("banner", "")
                    banner_str = f" ({banner})" if banner else ""
                    print(f"  [+] Port {port_num} | Service: {service_name}{banner_str}")
            else:
                print("  No open ports detected")

            # 4. Technologies, Cloud & WAF
            techs = [a.get("asset_value") for a in assets.get("technology", []) if a.get("asset_value")]
            clouds = [a.get("asset_value") for a in assets.get("cloud_provider", []) if a.get("asset_value")]
            cdns = [a.get("asset_value") for a in assets.get("cdn_provider", []) if a.get("asset_value")]
            wafs = [a.get("asset_value") for a in assets.get("waf", []) if a.get("asset_value")]
            
            print(f"\n--- FINGERPRINTED TECHNOLOGIES & INFRASTRUCTURE ---")
            print(f"  Technologies     : {', '.join(techs) if techs else 'None'}")
            print(f"  Cloud Providers  : {', '.join(clouds) if clouds else 'None'}")
            print(f"  CDN Providers    : {', '.join(cdns) if cdns else 'None'}")
            print(f"  WAF Protection   : {', '.join(wafs) if wafs else 'None'}")

            # 5. Mail Servers & Nameservers
            mail_servers = [a.get("asset_value") for a in assets.get("mail_server", []) if a.get("asset_value")]
            nameservers = [a.get("asset_value") for a in assets.get("nameserver", []) if a.get("asset_value")]
            print(f"\n--- MAIL & NAME SERVERS ---")
            print(f"  Mail Servers (MX): {', '.join(mail_servers) if mail_servers else 'None'}")
            print(f"  Nameservers (NS) : {', '.join(nameservers) if nameservers else 'None'}")

            # 6. Analyzers (Admin, Login, Staging, API)
            analyzers = attack_surface.get("analyzers", {})
            admin_portals = analyzers.get("admin_portals", {}).get("admin_portals", [])
            login_portals = analyzers.get("login_portals", {}).get("login_portals", [])
            staging_envs = analyzers.get("staging_environments", {}).get("staging_environments", [])
            api_endpoints = analyzers.get("api_endpoints", {}).get("api_endpoints", [])

            total_analyzed = len(admin_portals) + len(login_portals) + len(staging_envs) + len(api_endpoints)
            print(f"\n--- ANALYZER FINDINGS ({total_analyzed}) ---")
            if admin_portals:
                for item in admin_portals:
                    print(f"  [!] Admin Portal: {item.get('url')}")
            if login_portals:
                for item in login_portals:
                    print(f"  [!] Login Portal: {item.get('url')}")
            if staging_envs:
                for item in staging_envs:
                    print(f"  [!] Staging Env : {item.get('subdomain')}")
            if api_endpoints:
                for item in api_endpoints:
                    print(f"  [!] API Endpoint: {item.get('url')}")
            if total_analyzed == 0:
                print("  No special portals or endpoints detected")

            # Save full report to disk for inspection
            output_file = "last_scan_report.json"
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, default=str)
            print(f"\n==========================================")
            print(f"Detailed full report saved to: {output_file}")
            print(f"==========================================\n")

    except Exception as e:
        print(f"\n[ERROR] Scan failed: {e}")
    finally:
        await close_db()

if __name__ == "__main__":
    asyncio.run(main())
