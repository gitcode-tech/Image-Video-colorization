import argparse
from beautifultable import BeautifulTable
from colorama import Fore
from collections import Counter
from regFormat import PATTERNS

class LogRay:
    
    def __init__(self, logFile, thr: int=4):
        self.logFile: str = logFile
        self.thr: int = thr
        self.ipAdds: dict = {}
        
    def start(self):
        print(Fore.WHITE +
            '''\n
     █████                         ███████████                       
    ▒▒███                         ▒▒███▒▒▒▒▒███                      
     ▒███         ██████   ███████ ▒███    ▒███   ██████   █████ ████
     ▒███        ███▒▒███ ███▒▒███ ▒██████████   ▒▒▒▒▒███ ▒▒███ ▒███ 
     ▒███       ▒███ ▒███▒███ ▒███ ▒███▒▒▒▒▒███   ███████  ▒███ ▒███ 
     ▒███      █▒███ ▒███▒███ ▒███ ▒███    ▒███  ███▒▒███  ▒███ ▒███ 
     ███████████▒▒██████ ▒▒███████ █████   █████▒▒████████ ▒▒███████ 
    ▒▒▒▒▒▒▒▒▒▒▒  ▒▒▒▒▒▒   ▒▒▒▒▒███▒▒▒▒▒   ▒▒▒▒▒  ▒▒▒▒▒▒▒▒   ▒▒▒▒▒███ 
                          ███ ▒███                          ███ ▒███ 
                         ▒▒██████                          ▒▒██████  
                          ▒▒▒▒▒▒                            ▒▒▒▒▒▒   
                                  
                          V1.0, By 0xieee\n
            '''
        )
        
    def failPattern(self, lines: list, patterns, sample_size: int = 200, min_hits: int = 3):
        sample = lines[:sample_size]
        hits = {}
        for name, regex in patterns:
            count = 0
            for line in sample:
                if regex.search(line):
                    count += 1
            hits[name] = count
        bestName = max(hits, key=hits.get) # type: ignore
        bestHits = hits[bestName]
        bestRegex = None
        for patName, patRegex in patterns:
            if patName == bestName:
                bestRegex = patRegex
                break

        if bestRegex and bestHits >= min_hits:
            return bestName, bestRegex, hits
        else:
            return None, None, hits
    
    def ipExtract(self, match):
        if not match:
            return None
        try:
            # for patterns using name group "ip"
            ip_address = match.group("ip")
            return ip_address if ip_address else None
        except (IndexError, KeyError):
            # for old patterns
            for group_val in match.groups():
                if group_val and ('.' in group_val or ':' in group_val):
                    return group_val
            return None
    
    def logParser(self):
        attempts: list = []
        
        # open log file
        try:
            with open(self.logFile, "r", encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except FileNotFoundError:
            print(Fore.RED + "[-] Log file not found!")
            return False

        # find best pattern
        bestName, bestRegex, sampleHits = self.failPattern(lines, PATTERNS)
        
        # make them public (for report)
        self.bestName = bestName
        self.sampleHits = sampleHits
        
        self.detected_pattern = bestName
        self.active_patterns = PATTERNS

        # parse lines
        for line in lines:
            for name, regex in self.active_patterns:
                match = regex.search(line) # search line for regex match
                if match:
                    ip = self.ipExtract(match)
                    if ip:
                        attempts.append(ip)
                    break # once matched skip checking other patterns

        self.counter = Counter(attempts)
        return True
    
    def detection(self): # detect the suspicious ip by check the counter and send to report
        if not self.logParser():
            return
        else:
            for ip, count in self.counter.items():
                if count >= self.thr:
                    self.ipAdds[ip] = count
            
            self.report(sample_hits=getattr(self, "sampleHits"), detected_pattern=getattr(self, "bestName"))
            
    def report(self, sample_hits, detected_pattern): # print analysis report
        print(Fore.WHITE + "\n"+"="*34)
        print("     LogRay ANALYSIS REPORT!")
        print("="*34)
        
        # make table to show patterns and hits (+sort)
        table1 = BeautifulTable()
        table1.columns.header = ["Pattern", "Hits"]
        for name, count in sample_hits.items():
            table1.rows.append([name, count])
        table1.rows.sort(key=lambda x: x[1], reverse=True)
        print(Fore.YELLOW + "\n[*] Pattern Hits in Sample:")
        print(table1)
        
        if detected_pattern:
            print(Fore.RED + f"[+] Detected pattern: {detected_pattern}" + Fore.WHITE + "\n\n" + "="*34)
        else:
            print(Fore.GREEN + "[*] No single dominant pattern detected. Falling back to trying all patterns." + Fore.WHITE)

        if not self.ipAdds:
            print(Fore.GREEN + "[+] no suspicious activity found.\n" + Fore.WHITE)
            
        else:
            table2 = BeautifulTable()
            table2.columns.header = ["IP", "Attempts"]
            for ip, count in self.ipAdds.items():
                table2.rows.append([ip, count])
            print(Fore.RED + "\n[*] Suspicious IPs:")
            print(table2)
            print(Fore.GREEN + "[+] Recommended Action: Isolate IP and check logs.\n"+ Fore.WHITE)
            
if __name__ == "__main__":
    prs = argparse.ArgumentParser(
        description="LogRay(v1.0) - Detect bruteforce attempts in various log formats"
    )
    prs.add_argument(
        "-f", "--file",
        required=True,
        help="Path to the log file"
    )
    prs.add_argument(
        "-t", "--threshold",
        type=int,
        default=4,
        help="Number of failed attempts before flagging (default: 4)"
    )

    args = prs.parse_args()
    analysis = LogRay(logFile=args.file, thr=args.threshold)
    analysis.start()
    analysis.detection()