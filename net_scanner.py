import argparse
from numpy import save
import scapy.all as scapy
import os
import pandas as pd 
import requests


def get_args():
    
    #interface
    parser = argparse.ArgumentParser(prog= "Network Scanner", 
                                     description= "A Network Scanner based on ARP protocol by Jorge Corral",
                                     epilog= "Remember be careful with sensitive information")
    
    parser.add_argument('-t', '--target', help= 'Provide IPv4 net range')
    parser.add_argument('-v', '--verbose', help= 'Turn on verbose mode',
                        action= 'store_true')
    parser.add_argument('-o', dest='fout', help= 'Save program output to a file')
    parser.add_argument('-g', dest='getheader', help= 'Get the header of the website')
    
    args = parser.parse_args()
    
    return args

def get_header(website):
    
    res = []
    
    try:
        url = requests.get(url= website)
        header = dict(url.headers)
        for element in header:
            res.append(element + " : " + header[element])
        
        return res
        
    
    except:
        print(f'Website {website} unreachable')

def net_scan(net):
    
    
    #Make an ARP request by the net
    arp_req = scapy.ARP(pdst = net)
    
    #Make an Ether broadcast  
    broadcast = scapy.Ether(dst = 'ff:ff:ff:ff:ff:ff')
    
    arp_broad_req = broadcast/arp_req
    
    #send and receive level two packets, wait until 2, no verbose
    ans, unans = scapy.srp(arp_broad_req, timeout=2, verbose=False)
    
    res_dict = {}
    ips = []
    macs = []
    
    for item in ans:
        ips.append(item[1].psrc)
        macs.append(item[1].hwsrc)
        
        
    res_dict['IP_ADDRESS'] = ips
    res_dict['MAC_ADDRESS'] = macs
    
    
    return ans, unans, res_dict
    
def print_results_netscan(results, verbose = False):
    
    ans = results[0]
    unans = results[1]
    
    
    print('MAC Address\t\tIP Address')
    print(35 * '-')
    for element in ans:
        print(element[1].psrc + '\t' + element[1].hwsrc)
    
    if verbose:
        print('\nPrinting unanswered summary')
        print(35 * '-')
        for element in unans:
            print(element.summary)

def save_file(data):
    
    args = get_args()
    
    cwd = os.getcwd()
    df = pd.DataFrame(data)
    df.to_csv(args.fout, index = False)
    print(f'Results has been save under the following directory {cwd}')

def main():
    
    args = get_args()
    
    
    if args.target:
        results = net_scan(args.target)
        res_dict = results[2]
        
        if args.verbose == False:
            print_results_netscan(results)
        
        else:
            print_results_netscan(results, verbose = True)
            
        if args.fout:
            save_file(res_dict) 

    
    if args.getheader:
        header = get_header(args.getheader)
        try:
            for element in header:
                print(element)
                
            if args.fout:
                save_file(header)
                

        
                
        except:
            print('Can not connect, check the argument or conexion')
    
    
        

if __name__ == "__main__":
    main()

