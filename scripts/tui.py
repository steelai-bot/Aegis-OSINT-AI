#!/usr/bin/env python3
"""au-osint-recon :: tui.py -- Rich Terminal UI"""
import os, sys, json, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.align import Align
from rich.rule import Rule
from rich import box

console = Console()

def show_banner():
    console.print(Panel("[bold green]AU-OSINT-RECON v1.0\nAustralian OSINT Recon & Breach Intelligence\n[dim]Red Team Edition[/dim][/bold green]", border_style="green", padding=(1,4)))
    console.print(Align.center("[dim]Email | Domain | Company | URL | Phone | ABN[/dim]\n"))

def main_menu():
    t = Table(title="[bold green]MAIN MENU[/bold green]", box=box.DOUBLE_EDGE, border_style="green", show_header=False, padding=(0,2))
    t.add_column("Key", style="bold cyan", width=5); t.add_column("Action", style="white"); t.add_column("Desc", style="dim")
    for k,a,d in [("1","Full Recon","Auto-detect, all modules"),("2","Email Search","Breach+paste+darkweb"),("3","Domain Recon","OSINT+breach+exploit"),("4","Company Intel","AU company recon"),("5","Exploit Scan","SQLi XSS SSRF LFI SSTI CMDi"),("6","Dark Web","Forums, marketplaces"),("7","Telegram","Leak channels, MTProto"),("8","Paste Scraper","Pastebin, GitHub"),("9","Phone Lookup","AU carrier, reverse"),("10","ABN Lookup","Business Register"),("11","Cred Parser","combo/SQL/CSV dumps"),("12","Config","API keys"),("0","Exit","")]:
        t.add_row(k, a, d)
    console.print(t)
    return Prompt.ask("[green]>[/green] Option", choices=[str(i) for i in range(13)], default="1")

def select_modules():
    mods = ["breach","osint","exploit","darkweb","telegram","paste"]
    t = Table(box=box.ROUNDED, border_style="cyan"); t.add_column("#",style="bold cyan",width=3); t.add_column("Module")
    for i,m in enumerate(mods,1): t.add_row(str(i),m)
    t.add_row("A","[green]ALL[/green]"); console.print(t)
    ch = Prompt.ask("[cyan]>[/cyan] Modules (comma-sep or A)", default="A")
    if ch.upper()=="A": return mods
    return [mods[int(c.strip())-1] for c in ch.split(",") if c.strip().isdigit() and 1<=int(c.strip())<=6] or mods

def select_exploits():
    types = ["fingerprint","sqli","xss","ssrf","lfi","ssti","cmdi","crlf","redirect"]
    t = Table(box=box.ROUNDED, border_style="red"); t.add_column("#",style="bold red",width=3); t.add_column("Type")
    for i,tp in enumerate(types,1): t.add_row(str(i),tp)
    t.add_row("A","[red]ALL[/red]"); console.print(t)
    ch = Prompt.ask("[red]>[/red] Types (comma-sep or A)", default="A")
    if ch.upper()=="A": return types
    return [types[int(c.strip())-1] for c in ch.split(",") if c.strip().isdigit() and 1<=int(c.strip())<=9] or types

def display_results(results):
    s = results.summary()
    console.print(Rule("[bold green]RESULTS[/bold green]", style="green"))
    st = Table(box=box.DOUBLE_EDGE, border_style="green", show_header=False)
    st.add_column("M",style="bold cyan"); st.add_column("V",style="bold white",justify="right")
    st.add_row("Findings",str(s["total_findings"])); st.add_row("Sources",str(len(s.get("by_source",{})))); st.add_row("Categories",str(len(s.get("by_category",{}))))
    console.print(Align.center(st))
    if s.get("by_category"):
        ct = Table(title="[cyan]By Category[/cyan]",box=box.ROUNDED,border_style="cyan")
        ct.add_column("Category"); ct.add_column("Count",style="green",justify="right"); ct.add_column("Bar",style="green")
        mx = max(s["by_category"].values())
        for c,n in sorted(s["by_category"].items(),key=lambda x:-x[1]):
            bl=int(n/mx*25); ct.add_row(c,str(n),chr(9608)*bl+chr(9617)*(25-bl))
        console.print(ct)
    if results.findings:
        dt = Table(title="[yellow]Top Findings[/yellow]",box=box.ROUNDED,border_style="yellow",show_lines=True)
        dt.add_column("#",width=3); dt.add_column("Source",style="cyan",width=18); dt.add_column("Category",width=18); dt.add_column("Conf",width=6,justify="center"); dt.add_column("Data",style="dim",max_width=45)
        for i,f in enumerate(sorted(results.findings,key=lambda x:-x.confidence)[:20],1):
            cp=f"{f.confidence:.0%}"; cs="[red]" if f.confidence>=0.9 else "[yellow]" if f.confidence>=0.7 else "[cyan]"
            dt.add_row(str(i),f.source,f.category,f"{cs}{cp}[/]",json.dumps(f.data,default=str)[:45])
        console.print(dt)
        if len(results.findings)>20: console.print(f"  [dim]+{len(results.findings)-20} more[/dim]")

CONFIG_FILE = os.path.expanduser("~/.au_osint_config.json")
def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f: return json.load(f)
    return {}
def save_config(c):
    with open(CONFIG_FILE,"w") as f: json.dump(c,f,indent=2)

def config_menu():
    cfg = load_config()
    keys=["HIBP_API_KEY","DEHASHED_API_KEY","DEHASHED_EMAIL","INTELX_API_KEY","LEAKCHECK_API_KEY","SNUSBASE_API_KEY","TELEGRAM_API_ID","TELEGRAM_API_HASH","GITHUB_TOKEN"]
    t = Table(title="[green]Config[/green]",box=box.ROUNDED,border_style="green"); t.add_column("#",width=3); t.add_column("Key"); t.add_column("Status",width=10)
    for i,k in enumerate(keys,1): t.add_row(str(i),k,"[green]Set[/green]" if cfg.get(k,os.getenv(k,"")) else "[red]Empty[/red]")
    console.print(t)
    while True:
        ch=Prompt.ask("[green]>[/green] # or done",default="done")
        if ch=="done": break
        if ch.isdigit() and 1<=int(ch)<=len(keys):
            v=Prompt.ask(f"  {keys[int(ch)-1]}")
            if v: cfg[keys[int(ch)-1]]=v; save_config(cfg); console.print("  [green]Saved[/green]")

def run_scan(target,ttype,modules,etypes=None):
    from orchestrator import AUOSINTOrchestrator
    orch = AUOSINTOrchestrator(load_config())
    console.print(Rule("[green]SCANNING[/green]",style="green"))
    console.print(f"  Target: [bold]{target}[/bold] | Type: {ttype} | Modules: {','.join(modules)}\n")
    ml={"breach":"Breach","osint":"OSINT","exploit":"Exploit","darkweb":"DarkWeb","telegram":"Telegram","paste":"Paste"}
    with Progress(SpinnerColumn("dots"),TextColumn("[progress.description]{task.description}"),BarColumn(30),TaskProgressColumn(),TextColumn("[dim]{task.fields[status]}[/dim]"),console=console) as prog:
        mt=prog.add_task("[green]Overall",total=len(modules),status="go")
        for i,mod in enumerate(modules):
            tk=prog.add_task(f"  {ml.get(mod,mod)}",total=100,status="init")
            try:
                prog.update(tk,advance=20,status="querying...")
                if mod=="breach": r=orch.breach_engine.full_search(target,ttype if ttype in["email","domain","phone"] else "email"); orch._merge_results(r)
                elif mod=="osint": r=orch.au_osint.full_recon(target,ttype); orch._merge_results(r)
                elif mod=="exploit": r=orch.exploit_scanner.full_scan(target if target.startswith("http") else f"https://{target}",etypes); orch._merge_results(r)
                elif mod=="darkweb": r=orch.darkweb.full_search(target); orch._merge_results(r)
                elif mod=="telegram": r=orch.telegram.full_search(target); orch._merge_results(r)
                elif mod=="paste": r=orch.paste_scraper.full_search(target); orch._merge_results(r)
                prog.update(tk,completed=100,status=f"[green]{len(r) if hasattr(r,'__len__') else 0}[/green]")
            except Exception as e: prog.update(tk,completed=100,status=f"[red]{str(e)[:25]}[/red]")
            prog.update(mt,advance=1,status=f"{i+1}/{len(modules)}")
    orch.start_time=orch.start_time or time.time()-1; orch.end_time=time.time()
    display_results(orch.results)
    if Confirm.ask("[green]>[/green] Generate report?",default=True):
        od=Prompt.ask("[cyan]>[/cyan] Output dir",default="./au_osint_output")
        fm=Prompt.ask("[cyan]>[/cyan] Format",choices=["json","csv","html","all"],default="all")
        for fn,fp in orch.generate_report(od,fm).items(): console.print(f"  [green]OK[/green] {fn}: {fp}")
    return orch.results

def main():
    show_banner()
    while True:
        try:
            ch=main_menu()
            if ch=="0": console.print("\n[green]Bye.[/green]\n"); break
            elif ch=="1": run_scan(Prompt.ask("[green]>[/green] Target"),"auto",select_modules())
            elif ch=="2": run_scan(Prompt.ask("[green]>[/green] Email"),"email",select_modules())
            elif ch=="3": run_scan(Prompt.ask("[green]>[/green] Domain"),"domain",select_modules())
            elif ch=="4": run_scan(Prompt.ask("[green]>[/green] Company"),"company",select_modules())
            elif ch=="5": run_scan(Prompt.ask("[red]>[/red] URL"),"url",["exploit"],select_exploits())
            elif ch=="6": run_scan(Prompt.ask("[green]>[/green] Target"),"auto",["darkweb"])
            elif ch=="7": run_scan(Prompt.ask("[green]>[/green] Term"),"auto",["telegram"])
            elif ch=="8": run_scan(Prompt.ask("[green]>[/green] Target"),"auto",["paste"])
            elif ch=="9":
                from osint_australia import AustralianOSINT
                for f in AustralianOSINT().lookup_phone_au(Prompt.ask("[cyan]>[/cyan] Phone")): console.print(Panel(json.dumps(f.data,indent=2,default=str),title=f.source,border_style="cyan"))
            elif ch=="10":
                from osint_australia import AustralianOSINT
                for f in AustralianOSINT().lookup_abn(Prompt.ask("[cyan]>[/cyan] ABN")): console.print(Panel(json.dumps(f.data,indent=2,default=str),title=f.source,border_style="green"))
            elif ch=="11":
                from credential_parser import CredentialParser
                fp=Prompt.ask("[yellow]>[/yellow] File")
                if os.path.exists(fp):
                    cp=CredentialParser(); creds=cp.parse_sql_dump(fp) if fp.endswith(".sql") else cp.parse_csv_dump(fp) if fp.endswith(".csv") else cp.parse_combo_file(fp)
                    console.print(f"[green]{len(creds)} creds[/green]")
                    if creds: console.print(Panel(json.dumps(cp.analyze(creds),indent=2,default=str)[:2000],title="Analysis",border_style="yellow"))
                else: console.print("[red]Not found[/red]")
            elif ch=="12": config_menu()
            if ch!="0": Prompt.ask("\n[dim]Enter...[/dim]")
        except KeyboardInterrupt: console.print("\n[yellow]Interrupted[/yellow]")
        except Exception as e: console.print(f"[red]{e}[/red]")

if __name__=="__main__": main()
