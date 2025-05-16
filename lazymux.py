## lazymux.py - Lazymux v4.0
##
import os, sys
import readline
from time import sleep as timeout
from core.lzmcore import *

def main():
    banner()
    print("   [01] 信息收集")
    print("   [02] 漏洞分析")
    print("   [03] 网络攻击")
    print("   [04] 数据库评估")
    print("   [05] 密码攻击")
    print("   [06] 无线攻击")
    print("   [07] 逆向工程")
    print("   [08] 漏洞利用工具")
    print("   [09] 嗅探与欺骗")
    print("   [10] 报告工具")
    print("   [11] 取证工具")
    print("   [12] 压力测试")
    print("   [13] 安装Linux发行版")
    print("   [14] Termux实用工具")
    print("   [15] Shell Function [.bashrc]")
    print("   [16] 安装CLI游戏")
    print("   [17] 恶意软件分析")
    print("   [18] 编译器/解释器")
    print("   [19] 社会工程学工具")
    print("\n   [99] 更新Lazymux")
    print("   [00] 退出Lazymux\n")
    lazymux = input("lzmx > set_install ")

    # 01 - Information Gathering
    if lazymux.strip() == "1" or lazymux.strip() == "01":
        print("\n    [01] Nmap：用于网络发现和安全审计的工具")
        print("    [02] Red Hawk：信息收集、漏洞扫描和爬取工具")
        print("    [03] D-TECT：用于渗透测试的多合一工具")
        print("    [04] sqlmap：自动SQL注入和数据库接管工具")
        print("    [05] Infoga：收集电子邮件账户信息的工具")
        print("    [06] ReconDog：信息收集和漏洞扫描工具")
        print("    [07] AndroZenmap")
        print("    [08] sqlmate：SQLmap的辅助工具，实现你对SQLmap的期望功能")
        print("    [09] AstraNmap：用于在计算机网络中查找主机和服务的安全扫描器")
        print("    [10] MapEye：精确的GPS定位追踪器（支持Android、IOS、Windows手机）")
        print("    [11] Easymap：Nmap快捷方式")
        print("    [12] BlackBox：一个渗透测试框架")
        print("    [13] XD3v：功能强大的工具，可获取手机的所有基本细节信息")
        print("    [14] Crips：在线IP工具集合，可快速获取IP地址、网页和DNS记录信息")
        print("    [15] SIR：从网络解析Skype名称的最后已知IP")
        print("    [16] EvilURL：生成用于IDN同形异义词攻击的Unicode恶意域名并检测")
        print("    [17] Striker：侦察与漏洞扫描套件")
        print("    [18] Xshell：工具包")
        print("    [19] OWScan：OVID网络扫描器")
        print("    [20] OSIF：开源信息Facebook工具")
        print("    [21] Devploit：简单的信息收集工具")
        print("    [22] Namechk：基于namechk.com的OSINT工具，检查100+平台的用户名")
        print("    [23] AUXILE：Web应用程序分析框架")
        print("    [24] inther：使用Shodan、Censys和Hackertarget进行信息收集")
        print("    [25] GINF：GitHub信息收集工具")
        print("    [26] GPS追踪")
        print("    [27] ASU：Facebook黑客工具包")
        print("    [28] fim：Facebook图片下载器")
        print("    [29] MaxSubdoFinder：子域名发现工具")
        print("    [30] pwnedOrNot：查找已泄露电子邮件账户密码的OSINT工具")
        print("    [31] Mac-Lookup：查询特定Mac地址的信息")
        print("    [32] BillCipher：网站或IP地址的信息收集工具")
        print("    [33] dnsrecon：安全评估和网络故障排除工具")
        print("    [34] zphisher：自动化钓鱼工具")
        print("    [35] Mr.SIP：基于SIP协议的审计和攻击工具")
        print("    [36] Sherlock：通过用户名追踪社交媒体账户")
        print("    [37] userrecon：在75+社交网络中查找用户名")
        print("    [38] PhoneInfoga：使用免费资源扫描电话号码的先进工具")
        print("    [39] SiteBroker：基于Python的跨平台工具，用于信息收集和渗透测试自动化")
        print("    [40] maigret：通过用户名从数千个网站收集个人档案")
        print("    [41] GatheTOOL：基于hackertarget.com API的信息收集工具")
        print("    [42] ADB-ToolKit")
        print("    [43] TekDefense-Automater：IP、URL和MD5的OSINT分析工具")
        print("    [44] EagleEye：通过图像识别和反向搜索查找社交媒体账号（Instagram/FB/Twitter）")
        print("    [45] EyeWitness：截取网站截图、获取服务器头信息并识别默认凭据")
        print("    [46] InSpy：基于Python的LinkedIn账户枚举工具")
        print("    [47] Leaked：检查哈希值、密码和电子邮件是否泄露的工具")
        print("    [48] fierce：定位不连续IP空间的DNS侦察工具")
        print("    [49] gasmask：OSINT信息收集工具")
        print("    [50] osi.ig：Instagram信息收集工具")
        print("    [51] proxy-checker：检查代理有效性的简单脚本")
        print("\n    [00] 返回主菜单\n")
        infogathering = input("lzmx > set_install ")
        if infogathering == "@":
            infogathering = ""
            for x in range(1,201):
                infogathering += f"{x} "
        if len(infogathering.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for infox in infogathering.split():
            if infox.strip() == "01" or infox.strip() == "1": nmap()
            elif infox.strip() == "02" or infox.strip() == "2": red_hawk()
            elif infox.strip() == "03" or infox.strip() == "3": dtect()
            elif infox.strip() == "04" or infox.strip() == "4": sqlmap()
            elif infox.strip() == "05" or infox.strip() == "5": infoga()
            elif infox.strip() == "06" or infox.strip() == "6": reconDog()
            elif infox.strip() == "07" or infox.strip() == "7": androZenmap()
            elif infox.strip() == "08" or infox.strip() == "8": sqlmate()
            elif infox.strip() == "09" or infox.strip() == "9": astraNmap()
            elif infox.strip() == "10": mapeye()
            elif infox.strip() == "11": easyMap()
            elif infox.strip() == "12": blackbox()
            elif infox.strip() == "13": xd3v()
            elif infox.strip() == "14": crips()
            elif infox.strip() == "15": sir()
            elif infox.strip() == "16": evilURL()
            elif infox.strip() == "17": striker()
            elif infox.strip() == "18": xshell()
            elif infox.strip() == "19": owscan()
            elif infox.strip() == "20": osif()
            elif infox.strip() == "21": devploit()
            elif infox.strip() == "22": namechk()
            elif infox.strip() == "23": auxile()
            elif infox.strip() == "24": inther()
            elif infox.strip() == "25": ginf()
            elif infox.strip() == "26": gpstr()
            elif infox.strip() == "27": asu()
            elif infox.strip() == "28": fim()
            elif infox.strip() == "29": maxsubdofinder()
            elif infox.strip() == "30": pwnedOrNot()
            elif infox.strip() == "31": maclook()
            elif infox.strip() == "32": billcypher()
            elif infox.strip() == "33": dnsrecon()
            elif infox.strip() == "34": zphisher()
            elif infox.strip() == "35": mrsip()
            elif infox.strip() == "36": sherlock()
            elif infox.strip() == "37": userrecon()
            elif infox.strip() == "38": phoneinfoga()
            elif infox.strip() == "39": sitebroker()
            elif infox.strip() == "40": maigret()
            elif infox.strip() == "41": gathetool()
            elif infox.strip() == "42": adbtk()
            elif infox.strip() == "43": tekdefense()
            elif infox.strip() == "44": eagleeye()
            elif infox.strip() == "45": eyewitness()
            elif infox.strip() == "46": inspy()
            elif infox.strip() == "47": leaked()
            elif infox.strip() == "48": fierce()
            elif infox.strip() == "49": gasmask()
            elif infox.strip() == "50": osi_ig()
            elif infox.strip() == "51": proxy_checker()
            elif infox.strip() == "00" or infox.strip() == "0": restart_program()
            else: print("\n错误:输入错误");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)

    # 02 - Vulnerability Analysis
    elif lazymux.strip() == "2" or lazymux.strip() == "02":
        print("\n    [01] Nmap：用于网络发现和安全审计的工具")
        print("    [02] AndroZenmap")
        print("    [03] AstraNmap：用于在计算机网络中查找主机和服务的安全扫描器")
        print("    [04] Easymap：Nmap快捷方式")
        print("    [05] Red Hawk：信息收集、漏洞扫描和爬取工具")
        print("    [06] D-TECT：用于渗透测试的多合一工具")
        print("    [07] Damn Small SQLi Scanner：一个功能齐全的SQL注入漏洞扫描器（支持GET和POST参数），用不到100行代码编写")
        print("    [08] SQLiv：大规模SQL注入漏洞扫描器")
        print("    [09] sqlmap：自动SQL注入和数据库接管工具")
        print("    [10] sqlscan：快速SQL扫描器、漏洞利用工具、PHP webshell注入器")
        print("    [11] Wordpresscan：用Python重写的WPScan + 一些WPSeku的想法")
        print("    [12] WPScan：免费的WordPress安全扫描器")
        print("    [13] sqlmate：SQLmap的辅助工具，实现对SQLmap的期望功能")
        print("    [14] termux-wordpresscan")
        print("    [15] TM-scanner：用于Termux的网站漏洞扫描器")
        print("    [16] Rang3r：多线程IP + 端口扫描器")
        print("    [17] Striker：侦察与漏洞扫描套件")
        print("    [18] Routersploit：嵌入式设备利用框架")
        print("    [19] Xshell:工具包")
        print("    [20] SH33LL：Shell扫描器")
        print("    [21] BlackBox：一个渗透测试框架")
        print("    [22] XAttacker：网站漏洞扫描器和自动利用工具")
        print("    [23] OWScan：OVID网络扫描器")
        print("    [24] XPL-SEARCH：在多个漏洞数据库中搜索漏洞利用代码")
        print("    [25] AndroBugs_Framework：高效的Android漏洞扫描器，帮助发现应用潜在安全漏洞")
        print("    [26] Clickjacking-Tester：检查网站点击劫持漏洞并创建POC的Python脚本")
        print("    [27] Sn1per：攻击面管理平台 | Sn1perSecurity LLC")
        print("\n    [00] 返回主菜单\n")
        vulnsys = input("lzmx > set_install ")
        if vulnsys == "@":
            vulnsys = ""
            for x in range(1,201):
                vulnsys += f"{x} "
        if len(vulnsys.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for vulnx in vulnsys.split():
            if vulnsys.strip() == "01" or vulnsys.strip() == "1": nmap()
            elif vulnsys.strip() == "02" or vulnsys.strip() == "2": androZenmap()
            elif vulnsys.strip() == "03" or vulnsys.strip() == "3": astraNmap()
            elif vulnsys.strip() == "04" or vulnsys.strip() == "4": easyMap()
            elif vulnsys.strip() == "05" or vulnsys.strip() == "5": red_hawk()
            elif vulnsys.strip() == "06" or vulnsys.strip() == "6": dtect()
            elif vulnsys.strip() == "07" or vulnsys.strip() == "7": dsss()
            elif vulnsys.strip() == "08" or vulnsys.strip() == "8": sqliv()
            elif vulnsys.strip() == "09" or vulnsys.strip() == "9": sqlmap()
            elif vulnsys.strip() == "10": sqlscan()
            elif vulnsys.strip() == "11": wordpreSScan()
            elif vulnsys.strip() == "12": wpscan()
            elif vulnsys.strip() == "13": sqlmate()
            elif vulnsys.strip() == "14": wordpresscan()
            elif vulnsys.strip() == "15": tmscanner()
            elif vulnsys.strip() == "16": rang3r()
            elif vulnsys.strip() == "17": striker()
            elif vulnsys.strip() == "18": routersploit()
            elif vulnsys.strip() == "19": xshell()
            elif vulnsys.strip() == "20": sh33ll()
            elif vulnsys.strip() == "21": blackbox()
            elif vulnsys.strip() == "22": xattacker()
            elif vulnsys.strip() == "23": owscan()
            elif vulnsys.strip() == "24": xplsearch()
            elif vulnsys.strip() == "25": androbugs()
            elif vulnsys.strip() == "26": clickjacking()
            elif vulnsys.strip() == "27": sn1per()
            elif vulnsys.strip() == "00" or vulnsys.strip() == "0": restart_program()
            else: print("\n错误:输入错误");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)

    # 03 - Web Hacking
    elif lazymux.strip() == "3" or lazymux.strip() == "03":
        print("\n    [01] sqlmap：自动SQL注入与数据库接管工具")
        print("    [02] WebDAV：WebDAV文件上传漏洞利用工具")
        print("    [03] MaxSubdoFinder：子域名发现工具")
        print("    [04] Webdav Mass Exploit：WebDAV批量漏洞利用工具")
        print("    [5]Atlas：快速SQLMap绕过脚本建议工具")
        print("    [06] sqldump：轻松导出SQL结果站点数据工具")
        print("    [07] Websploit：高级中间人攻击（MiTM）框架")
        print("    [08] sqlmate：SQLmap辅助工具，实现你对SQLmap的预期功能")
        print("    [09] inther：利用Shodan、Censys和Hackertarget进行信息收集工具")
        print("    [10] HPB：HTML页面生成器")
        print("    [11] Xshell：工具包")
        print("    [12] SH33LL：Shell扫描器")
        print("    [13] XAttacker：网站漏洞扫描与自动利用工具")
        print("    [14] XSStrike：最先进的跨站脚本（XSS）扫描器")
        print("    [15] Breacher：高级多线程管理面板查找工具")
        print("    [16] OWScan：OVID Web扫描器")
        print("    [17] ko-dork：简单漏洞Web扫描器")
        print("    [18] ApSca：强大的Web渗透测试应用程序")
        print("    [19] amox：通过字典攻击查找网站后门或Shell工具")
        print("    [20] FaDe：利用kindeditor、fckeditor和webdav进行虚假篡改工具")
        print("    [21] AUXILE：Auxile框架")
        print("    [22] xss-payload-list：跨站脚本（XSS）漏洞Payload列表")
        print("    [23] Xadmin：管理面板查找工具")
        print("    [24] CMSeeK：内容管理系统（CMS）检测与利用套件，支持扫描WordPress、Joomla、Drupal等180+种CMS")
        print("    [25] CMSmap：开源Python CMS扫描器，自动检测主流CMS安全漏洞")
        print("    [26] CrawlBox：暴力破解Web目录工具")
        print("    [27] LFISuite：全自动本地文件包含（LFI）漏洞利用（含反向Shell）与扫描工具")
        print("    [28] Parsero：Robots.txt审计工具")
        print("    [29] Sn1per：攻击面管理平台（Sn1perSecurity LLC开发）")
        print("    [30] Sublist3r：渗透测试人员使用的快速子域名枚举工具")
        print("    [31] WP-plugin-scanner：列出WordPress网站安装插件的工具")
        print("    [32] WhatWeb：下一代Web扫描器")
        print("    [33] fuxploider：文件上传漏洞扫描与利用工具")
        print("\n    [00] 返回主菜单\n")
        webhack = input("lzmx > set_install ")
        if webhack == "@":
            webhack = ""
            for x in range(1,201):
                webhack += f"{x} "
        if len(webhack.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for webhx in webhack.split():
            if webhx.strip() == "01" or webhx.strip() == "1": sqlmap()
            elif webhx.strip() == "02" or webhx.strip() == "2": webdav()
            elif webhx.strip() == "03" or webhx.strip() == "3": maxsubdofinder()
            elif webhx.strip() == "04" or webhx.strip() == "4": webmassploit()
            elif webhx.strip() == "05" or webhx.strip() == "5": atlas()
            elif webhx.strip() == "06" or webhx.strip() == "6": sqldump()
            elif webhx.strip() == "07" or webhx.strip() == "7": websploit()
            elif webhx.strip() == "08" or webhx.strip() == "8": sqlmate()
            elif webhx.strip() == "09" or webhx.strip() == "9": inther()
            elif webhx.strip() == "10": hpb()
            elif webhx.strip() == "11": xshell()
            elif webhx.strip() == "12": sh33ll()
            elif webhx.strip() == "13": xattacker()
            elif webhx.strip() == "14": xsstrike()
            elif webhx.strip() == "15": breacher()
            elif webhx.strip() == "16": owscan()
            elif webhx.strip() == "17": kodork()
            elif webhx.strip() == "18": apsca()
            elif webhx.strip() == "19": amox()
            elif webhx.strip() == "20": fade()
            elif webhx.strip() == "21": auxile()
            elif webhx.strip() == "22": xss_payload_list()
            elif webhx.strip() == "23": xadmin()
            elif webhx.strip() == "24": cmseek()
            elif webhx.strip() == "25": cmsmap()
            elif webhx.strip() == "26": crawlbox()
            elif webhx.strip() == "27": lfisuite()
            elif webhx.strip() == "28": parsero()
            elif webhx.strip() == "29": sn1per()
            elif webhx.strip() == "30": sublist3r()
            elif webhx.strip() == "31": wppluginscanner()
            elif webhx.strip() == "32": whatweb()
            elif webhx.strip() == "33": fuxploider()
            elif webhx.strip() == "00" or webhx.strip() == "0": restart_program()
            else: print("\n错误:输入错误");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 04 - Database Assessment
    elif lazymux.strip() == "4" or lazymux.strip() == "04":
        print("\n    [01] DbDat：对数据库执行多项安全检查评估的工具")
        print("    [02] sqlmap：自动SQL注入与数据库接管工具")
        print("    [03] NoSQLMap：自动化NoSQL数据库枚举及Web应用漏洞利用工具")
        print("    [04] audit_couchdb：检测CouchDB服务器中各类安全问题的工具")
        print("    [05] mongoaudit：自动化渗透测试工具，检测MongoDB实例安全配置是否合规")
        print("\n    [00] 返回主菜单\n")
        dbssm = input("lzmx > set_install ")
        if dbssm == "@":
            dbssm = ""
            for x in range(1,201):
                dbssm += f"{x} "
        if len(dbssm.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for dbsx in dbssm.split():
            if dbsx.strip() == "01" or dbsx.strip() == "1": dbdat()
            elif dbsx.strip() == "02" or dbsx.strip() == "2": sqlmap()
            elif dbsx.strip() == "03" or dbsx.strip() == "3": nosqlmap
            elif dbsx.strip() == "04" or dbsx.strip() == "4": audit_couchdb()
            elif dbsx.strip() == "05" or dbsx.strip() == "5": mongoaudit()
            elif dbsx.strip() == "00" or dbsx.strip() == "0": restart_program()
            else: print("\n错误:输入错误");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 05 - Password Attacks
    elif lazymux.strip() == "5" or lazymux.strip() == "05":
        print("\n    [01] Hydra：支持多服务的网络登录破解工具")
        print("    [02] FMBrute：Facebook多账号暴力破解工具")
        print("    [03] HashID：哈希类型识别软件")
        print("    [04] Facebook Brute Force 3：Facebook暴力破解工具（第三版）")
        print("    [05] Black Hydra：缩短Hydra暴力破解耗时的辅助程序")
        print("    [06] Hash Buster：秒级哈希破解工具")
        print("    [07] FBBrute：Facebook暴力破解工具")
        print("    [08] Cupp：用户密码特征分析生成工具")
        print("    [09] InstaHack：Instagram暴力破解工具")
        print("    [10] Indonesian Wordlist：印尼语密码字典")
        print("    [11] Xshell：工具包（具体功能未明确）")
        print("    [12] Aircrack-ng：WiFi安全审计工具套件")
        print("    [13] BlackBox：渗透测试框架")
        print("    [14] Katak：开源登录暴力破解与哈希解密工具包")
        print("    [15] Hasher：自动识别哈希类型的破解工具")
        print("    [16] Hash-Generator：哈希生成工具")
        print("    [17] nk26：Nkosec编码工具")
        print("    [18] Hasherdotid：加密文本查找工具")
        print("    [19] Crunch：高度可定制的密码字典生成器")
        print("    [20] Hashcat：全球最快的高级密码恢复工具")
        print("    [21] ASU：Facebook黑客工具包")
        print("    [22] Credmap：开源凭证重用风险警示工具")
        print("    [23] BruteX：自动暴力破解目标主机运行服务的工具")
        print("    [24] Gemail-Hack：Python脚本实现的")
        print("    [25] GoblinWordGenerator：Python密码字典生成器")
        print("    [26] PyBozoCrack：Python编写的MD5破解工具")
        print("    [27] brutespray：基于Nmap扫描结果的自动服务默认凭证破解工具")
        print("    [28] crowbar：渗透测试用暴力破解工具")
        print("    [29] elpscrk：基于用户画像、排列组合和统计的智能密码字典生成器")
        print("    [30] fbht：Facebook黑客工具")
        print("\n    [00] 返回主菜单\n")
        passtak = input("lzmx > set_install ")
        if passtak == "@":
            passtak = ""
            for x in range(1,201):
                passtak += f"{x} "
        if len(passtak.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for passx in passtak.split():
            if passx.strip() == "01" or passx.strip() == "1": hydra()
            elif passx.strip() == "02" or passx.strip() == "2": fmbrute()
            elif passx.strip() == "03" or passx.strip() == "3": hashid()
            elif passx.strip() == "04" or passx.strip() == "4": fbBrute()
            elif passx.strip() == "05" or passx.strip() == "5": black_hydra()
            elif passx.strip() == "06" or passx.strip() == "6": hash_buster()
            elif passx.strip() == "07" or passx.strip() == "7": fbbrutex()
            elif passx.strip() == "08" or passx.strip() == "8": cupp()
            elif passx.strip() == "09" or passx.strip() == "9": instaHack()
            elif passx.strip() == "10": indonesian_wordlist()
            elif passx.strip() == "11": xshell()
            elif passx.strip() == "12": aircrackng()
            elif passx.strip() == "13": blackbox()
            elif passx.strip() == "14": katak()
            elif passx.strip() == "15": hasher()
            elif passx.strip() == "16": hashgenerator()
            elif passx.strip() == "17": nk26()
            elif passx.strip() == "18": hasherdotid()
            elif passx.strip() == "19": crunch()
            elif passx.strip() == "20": hashcat()
            elif passx.strip() == "21": asu()
            elif passx.strip() == "22": credmap()
            elif passx.strip() == "23": brutex()
            elif passx.strip() == "24": gemailhack()
            elif passx.strip() == "25": goblinwordgenerator()
            elif passx.strip() == "26": pybozocrack()
            elif passx.strip() == "27": brutespray()
            elif passx.strip() == "28": crowbar()
            elif passx.strip() == "29": elpscrk()
            elif passx.strip() == "30": fbht()
            elif passx.strip() == "00" or passx.strip() == "0": restart_program()
            else: print("\n错误:输入错误");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 06 - Wireless Attacks
    elif lazymux.strip() == "6" or lazymux.strip() == "06":
        print("\n    [01] Aircrack-ng：WiFi安全审计工具套件")
        print("    [02] Wifite：自动化无线攻击工具")
        print("    [03] Wifiphisher： rogue接入点框架（用于钓鱼攻击）")
        print("    [04] Routersploit：嵌入式设备漏洞利用框架")
        print("    [05] PwnSTAR：伪造接入点（Fake-AP）工具脚本")
        print("    [06] Pyrit：知名WPA预计算哈希破解工具（源自Google迁移项目）")
        print("\n    [00] 返回主菜单\n")
        wiretak = input("lzmx > set_install ")
        if wiretak == "@":
            wiretak = ""
            for x in range(1,201):
                wiretak += f"{x} "
        if len(wiretak.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for wirex in wiretak.split():
            if wirex.strip() == "01" or wirex.strip() == "1": aircrackng()
            elif wirex.strip() == "02" or wirex.strip() == "2": wifite()
            elif wirex.strip() == "03" or wirex.strip() == "3": wifiphisher()
            elif wirex.strip() == "04" or wirex.strip() == "4": routersploit()
            elif wirex.strip() == "05" or wirex.strip() == "5": pwnstar()
            elif wirex.strip() == "06" or wirex.strip() == "6": pyrit()
            elif wirex.strip() == "00" or wirex.strip() == "0": restart_program()
            else: print("\n错误:输入错误");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 07 - Reverse Engineering
    elif lazymux.strip() == "7" or lazymux.strip() == "07":
        print("\n    [01] 二进制漏洞利用")
        print("    [02] jadx：DEX转JAVA反编译器")
        print("    [03] apktool：安卓应用逆向工程工具")
        print("    [04] uncompyle6：Python跨版本字节码反编译器")
        print("    [05] ddcrypt：DroidScript APK去混淆工具")
        print("    [06] CFR：另一款Java反编译器")
        print("    [07] UPX：可执行文件压缩工具")
        print("    [08] pyinstxtractor：PyInstaller程序解包工具")
        print("    [09] innoextract：Inno Setup安装包解包工具")
        print("    [10] pycdc：C++编写的Python字节码反汇编/反编译器")
        print("    [11] APKiD：安卓应用打包器、防护器、混淆器检测工具（安卓版PEiD）")
        print("    [12] DTL-X：Python安卓APK逆向与补丁工具")
        print("    [13] APKLeaks：APK文件URI、端点及敏感信息扫描工具")
        print("    [14] apk-mitm：自动配置安卓APK进行HTTPS抓包的CLI工具")
        print("    [15] ssl-pinning-remover：安卓应用SSL证书固定移除工具")
        print("    [16] GEF：GDB增强功能插件（Linux下为漏洞开发与逆向工程师提供现代调试体验）")
        print("\n    [00] 返回主菜单\n")
        reversi = input("lzmx > set_install ")
        if reversi == "@":
            reversi = ""
            for x in range(1,201):
                reversi += f"{x} "
        if len(reversi.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for revex in reversi.split():
            if revex.strip() == "01" or revex.strip() == "1": binploit()
            elif revex.strip() == "02" or revex.strip() == "2": jadx()
            elif revex.strip() == "03" or revex.strip() == "3": apktool()
            elif revex.strip() == "04" or revex.strip() == "4": uncompyle()
            elif revex.strip() == "05" or revex.strip() == "5": ddcrypt()
            elif revex.strip() == "06" or revex.strip() == "6": cfr()
            elif revex.strip() == "07" or revex.strip() == "7": upx()
            elif revex.strip() == "08" or revex.strip() == "8": pyinstxtractor()
            elif revex.strip() == "09" or revex.strip() == "9": innoextract()
            elif revex.strip() == "10": pycdc()
            elif revex.strip() == "11": apkid()
            elif revex.strip() == "12": dtlx()
            elif revex.strip() == "13": apkleaks()
            elif revex.strip() == "14": apkmitm()
            elif revex.strip() == "15": ssl_pinning_remover()
            elif revex.strip() == "16": gef()
            elif revex.strip() == "00" or revex.strip() == "0": restart_program()
            else: print("\n错误:输入错误");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 08 - Exploitation Tools
    elif lazymux.strip() == "8" or lazymux.strip() == "08":
        print("\n    [01] Metasploit：用于开发、测试和使用漏洞利用代码的高级开源平台")
        print("    [02] commix：全自动一体化操作系统命令注入与利用工具")
        print("    [03] BlackBox：渗透测试框架")
        print("    [04] Brutal：类似Teensy（橡胶鸭）的Payload工具，语法不同")
        print("    [05] TXTool：简易渗透测试工具")
        print("    [06] XAttacker：网站漏洞扫描与自动利用工具")  
        print("    [07] Websploit：高级中间人攻击（MiTM）框架")
        print("    [08] Routersploit：嵌入式设备漏洞利用框架")
        print("    [09] A-Rat：远程管理工具（后门程序）")
        print("    [10] BAF：盲攻击框架")
        print("    [11] Gloom-Framework：Linux渗透测试框架")
        print("    [12] Zerodoor：快速生成跨平台后门的脚本")
        print("\n    [00] 返回主菜单\n")
        exploitool = input("lzmx > set_install ")
        if exploitool == "@":
            exploitool = ""
            for x in range(1,201):
                exploitool += f"{x} "
        if len(exploitool.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for explx in exploitool.split():
            if explx.strip() == "01" or explx.strip() == "1": metasploit()
            elif explx.strip() == "02" or explx.strip() == "2": commix()
            elif explx.strip() == "03" or explx.strip() == "3": blackbox()
            elif explx.strip() == "04" or explx.strip() == "4": brutal()
            elif explx.strip() == "05" or explx.strip() == "5": txtool()
            elif explx.strip() == "06" or explx.strip() == "6": xattacker()
            elif explx.strip() == "07" or explx.strip() == "7": websploit()
            elif explx.strip() == "08" or explx.strip() == "8": routersploit()
            elif explx.strip() == "09" or explx.strip() == "9": arat()
            elif explx.strip() == "10": baf()
            elif explx.strip() == "11": gloomframework()
            elif explx.strip() == "12": zerodoor()
            elif explx.strip() == "00" or explx.strip() == "0": restart_program()
            else: print("\n错误:输入错误");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 09 - Sniffing and Spoofing
    elif lazymux.strip() == "9" or lazymux.strip() == "09":
        print("\n    [01] KnockMail：验证邮箱是否存在的工具")
        print("    [02] tcpdump：强大的命令行数据包分析工具")
        print("    [03] Ettercap：综合性中间人攻击套件，可嗅探实时连接、动态过滤内容等")
        print("    [04] hping3：命令行TCP/IP数据包构造与分析工具")
        print("    [05] tshark：网络协议分析与抓包工具")
        print("\n    [00] 返回主菜单\n")
        sspoof = input("lzmx > set_install ")
        if sspoof == "@":
            sspoof = ""
            for x in range(1,201):
                sspoof += f"{x} "
        if len(sspoof.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for sspx in sspoof.split():
            if sspx.strip() == "01" or sspx.strip() == "1": knockmail()
            elif sspx.strip() == "02" or sspx.strip() == "2": tcpdump()
            elif sspx.strip() == "03" or sspx.strip() == "3": ettercap()
            elif sspx.strip() == "04" or sspx.strip() == "4": hping3()
            elif sspx.strip() == "05" or sspx.strip() == "5": tshark()
            elif sspx.strip() == "00" or sspx.strip() == "0": restart_program()
            else: print("\n错误:输入错误");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 10 - Reporting Tools
    elif lazymux.strip() == "10":
        print("\n    [01] dos2unix：DOS与Unix文本文件格式转换工具")
        print("    [02] exiftool：读取、写入和编辑多种文件元信息的工具")
        print("    [03] iconv：不同字符编码转换工具")
        print("    [04] mediainfo：命令行媒体文件信息读取工具")
        print("    [05] pdfinfo：PDF文档信息提取工具")
        print("\n    [00] 返回主菜单\n")
        reportls = input("lzmx > set_install ")
        if reportls == "@":
            reportls = ""
            for x in range(1,201):
                reportls += f"{x} "
        if len(reportls.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for reportx in reportls.split():
            if reportx.strip() == "01" or reportx.strip() == "1": dos2unix()
            elif reportx.strip() == "02" or reportx.strip() == "2": exiftool()
            elif reportx.strip() == "03" or reportx.strip() == "3": iconv()
            elif reportx.strip() == "04" or reportx.strip() == "4": mediainfo()
            elif reportx.strip() == "05" or reportx.strip() == "5": pdfinfo()
            elif reportx.strip() == "00" or reportx.strip() == "0": restart_program()
            else: print("\n错误:输入错误");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 11 - Forensic Tools
    elif lazymux.strip() == "11":
        print("\n    [01] steghide：通过替换最低有效位在文件中嵌入消息的隐写工具")
        print("    [02] tesseract：可能是目前最精确的开源OCR（光学字符识别）引擎")
        print("    [03] sleuthkit：数字取证工具库（TSK）")
        print("    [04] CyberScan：网络取证工具包")
        print("    [05] binwalk：固件分析工具")
        print("\n    [00] 返回主菜单\n")
        forensc = input("lzmx > set_install ")
        if forensc == "@":
            forensc = ""
            for x in range(1,201):
                forensc += f"{x} "
        if len(forensc.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for forenx in forensc.split():
            if forenx.strip() == "01" or forenx.strip() == "1": steghide()
            elif forenx.strip() == "02" or forenx.strip() == "2": tesseract()
            elif forenx.strip() == "03" or forenx.strip() == "3": sleuthkit()
            elif forenx.strip() == "04" or forenx.strip() == "4": cyberscan()
            elif forenx.strip() == "05" or forenx.strip() == "5": binwalk()
            elif forenx.strip() == "00" or forenx.strip() == "0": restart_program()
            else: print("\n错误:输入错误");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 12 - Stress Testing
    elif lazymux.strip() == "12":
        print("\n    [01] Torshammer：慢速POST分布式拒绝服务（DDOS）攻击工具")
        print("    [02] Slowloris：低带宽拒绝服务（DoS）攻击工具")
        print("    [03] Fl00d & Fl00d2：UDP泛洪攻击工具")
        print("    [04] GoldenEye：基于七层协议（KeepAlive+NoCache）的DoS测试工具")
        print("    [05] Xerxes：高威力拒绝服务（DoS）攻击工具")
        print("    [06] Planetwork-DDOS：DDOS攻击工具")
        print("    [07] Xshell：工具包（功能未明确）")
        print("    [08] santet-online：社会工程学工具")
        print("    [09] dost-attack：Web服务器攻击工具")
        print("    [10] DHCPig：使用Scapy网络库编写的DHCP耗尽脚本")
        print("\n    [00] 返回主菜单\n")
        stresstest = input("lzmx > set_install ")
        if stresstest == "@":
            stresstest = ""
            for x in range(1,201):
                stresstest += f"{x} "
        if len(stresstest.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for stressx in stresstest.split():
            if stressx.strip() == "01" or stressx.strip() == "1": torshammer()
            elif stressx.strip() == "02" or stressx.strip() == "2": slowloris()
            elif stressx.strip() == "03" or stressx.strip() == "3": fl00d12()
            elif stressx.strip() == "04" or stressx.strip() == "4": goldeneye()
            elif stressx.strip() == "05" or stressx.strip() == "5": xerxes()
            elif stressx.strip() == "06" or stressx.strip() == "6": planetwork_ddos()
            elif stressx.strip() == "07" or stressx.strip() == "7": xshell()
            elif stressx.strip() == "08" or stressx.strip() == "8": sanlen()
            elif stressx.strip() == "09" or stressx.strip() == "9": dostattack()
            elif stressx.strip() == "10": dhcpig()
            elif stressx.strip() == "00" or stressx.strip() == "0": restart_program()
            else: print("\n错误:输入错误");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 13 - Install Linux Distro
    elif lazymux.strip() == "13":
        print("\n    [01] Ubuntu (impish)")
        print("    [02] Fedora")
        print("    [03] Kali Nethunter")
        print("    [04] Parrot")
        print("    [05] Arch Linux")
        print("    [06] Alpine Linux (edge)")
        print("    [07] Debian (bullseye)")
        print("    [08] Manjaro AArch64")
        print("    [09] OpenSUSE (Tumbleweed)")
        print("    [10] Void Linux")
        print("\n    [00] Back to main menu\n")
        innudis = input("lzmx > set_install ")
        if innudis == "@":
            innudis = ""
            for x in range(1,201):
                innudis += f"{x} "
        if len(innudis.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for innux in innudis.split():
            if innux.strip() == "01" or innux.strip() == "1": ubuntu()
            elif innux.strip() == "02" or innux.strip() == "2": fedora()
            elif innux.strip() == "03" or innux.strip() == "3": nethunter()
            elif innux.strip() == "04" or innux.strip() == "4": parrot()
            elif innux.strip() == "05" or innux.strip() == "5": archlinux()
            elif innux.strip() == "06" or innux.strip() == "6": alpine()
            elif innux.strip() == "07" or innux.strip() == "7": debian()
            elif innux.strip() == "08" or innux.strip() == "8": manjaroArm64()
            elif innux.strip() == "09" or innux.strip() == "9": opensuse()
            elif innux.strip() == "10": voidLinux()
            elif innux.strip() == "00" or innux.strip() == "0": restart_program()
            else: print("\n错误:输入错误");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 14 - Termux Utility
    elif lazymux.strip() == "14":
        print("\n    [01] SpiderBot：使用随机代理和用户代理抓取网站的工具")
        print("    [02] Ngrok：将本地端口映射到公共URL并监控流量的隧道工具")
        print("    [03] Sudo：安卓设备的sudo安装工具")
        print("    [04] google：Python调用谷歌搜索引擎的接口工具")
        print("    [05] kojawafft：未明确功能的工具（名称可能存在拼写错误）")
        print("    [06] ccgen：信用卡号生成工具（注：此类工具可能涉及非法用途，请勿用于不当行为）")
        print("    [07] VCRT：病毒创建工具")
        print("    [08] E-Code：PHP脚本加密工具")
        print("    [09] Termux-Styling：Termux终端界面美化工具")
        print("    [11] xl-py：XL直接购买程序包（功能描述模糊）")
        print("    [12] BeanShell：用Java编写的嵌入式脚本解释器（支持对象脚本语言特性）")
        print("    [13] vbug：病毒制作工具")
        print("    [14] Crunch：高度可定制的密码字典生成器")
        print("    [15] Textr：简易文本处理工具")
        print("    [16] heroku：Heroku平台交互的命令行工具")
        print("    [17] RShell：单监听反向Shell工具")
        print("    [18] TermPyter：修复Termux中Jupyter安装错误的工具")
        print("    [19] Numpy：Python科学计算基础库")
        print("    [20] BTC-to-IDR-checker：通过Bitcoin.co.id API查询比特币对印尼盾汇率的工具")
        print("    [21] ClickBot：通过Telegram机器人盈利的工具")
        print("    [22] pandas：开源数据操作与分析库")
        print("    [23] jupyter-notebook：支持代码、公式、可视化的交互式网页笔记工具")
        print("\n    [00] 返回主菜单\n")
        moretool = input("lzmx > set_install ")
        if moretool == "@":
            moretool = ""
            for x in range(1,201):
                moretool += f"{x} "
        if len(moretool.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for moret in moretool.split():
            if moret.strip() == "01" or moret.strip() == "1": spiderbot()
            elif moret.strip() == "02" or moret.strip() == "2": ngrok()
            elif moret.strip() == "03" or moret.strip() == "3": sudo()
            elif moret.strip() == "04" or moret.strip() == "4": google()
            elif moret.strip() == "05" or moret.strip() == "5": kojawafft()
            elif moret.strip() == "06" or moret.strip() == "6": ccgen()
            elif moret.strip() == "07" or moret.strip() == "7": vcrt()
            elif moret.strip() == "08" or moret.strip() == "8": ecode()
            elif moret.strip() == "09" or moret.strip() == "9": stylemux()
            elif moret.strip() == "10": passgencvar()
            elif moret.strip() == "11": xlPy()
            elif moret.strip() == "12": beanshell()
            elif moret.strip() == "13": vbug()
            elif moret.strip() == "14": crunch()
            elif moret.strip() == "15": textr()
            elif moret.strip() == "16": heroku()
            elif moret.strip() == "17": rshell()
            elif moret.strip() == "18": termpyter()
            elif moret.strip() == "19": numpy()
            elif moret.strip() == "20": btc2idr()
            elif moret.strip() == "21": clickbot()
            elif moret.strip() == "22": pandas()
            elif moret.strip() == "23": notebook()
            elif moret.strip() == "00" or moret.strip() == "0": restart_program()
            else: print("\n错误:输入错误");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 15 - Shell Function [.bashrc]
    elif lazymux.strip() == "15":
        print("\n    [01] FBVid：Facebook视频下载工具")
        print("    [02] cast2video：Asciinema录屏转换工具")
        print("    [03] iconset：AIDE应用图标制作工具")
        print("    [04] readme：GitHub README.md文件生成/管理工具")
        print("    [05] makedeb：DEB软件包构建工具")
        print("    [06] quikfind：文件搜索工具")
        print("    [07] pranayama：4-7-8呼吸放松工具")
        print("    [08] sqlc：SQLite查询处理工具")
        print("\n    [00] 返回主菜单\n")
        myshf = input("lzmx > set_install ")
        if myshf == "@":
            myshf = ""
            for x in range(1,201):
                myshf += f"{x} "
        if len(myshf.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for mysh in myshf.split():
            if mysh.strip() == "01" or mysh.strip() == "1": fbvid()
            elif mysh.strip() == "02" or mysh.strip() == "2": cast2video()
            elif mysh.strip() == "03" or mysh.strip() == "3": iconset()
            elif mysh.strip() == "04" or mysh.strip() == "4": readme()
            elif mysh.strip() == "05" or mysh.strip() == "5": makedeb()
            elif mysh.strip() == "06" or mysh.strip() == "6": quikfind()
            elif mysh.strip() == "07" or mysh.strip() == "7": pranayama()
            elif mysh.strip() == "08" or mysh.strip() == "8": sqlc()
            elif mysh.strip() == "00" or mysh.strip() == "0": restart_program()
            else: print("\n错误:输入错误");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 16 - Install CLI Games
    elif lazymux.strip() == "16":
        print("\n    [01] 飞扬的小鸟（经典像素跳跃游戏）")
        print("    [02] 街头汽车（模拟驾驶类游戏）")
        print("    [03] 快速打字（打字练习/竞速游戏）")
        print("    [04] NSnake：文本界面的经典贪吃蛇游戏")
        print("    [05] 月球车：驾驶车辆在月球表面行驶的简易游戏")
        print("    [06] Nudoku：基于ncurses的数独游戏")
        print("    [07] tty-solitaire：终端界面的纸牌接龙游戏")
        print("    [08] Pacman4Console：控制台版吃豆人游戏")
        print("\n    [00] 返回主菜单\n")
        cligam = input("lzmx > set_install ")
        if cligam == "@":
            cligam = ""
            for x in range(1,201):
                cligam += f"{x} "
        if len(cligam.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for clig in cligam.split():
            if clig.strip() == "01" or clig.strip() == "1": flappy_bird()
            elif clig.strip() == "02" or clig.strip() == "2": street_car()
            elif clig.strip() == "03" or clig.strip() == "3": speed_typing()
            elif clig.strip() == "04" or clig.strip() == "4": nsnake()
            elif clig.strip() == "05" or clig.strip() == "5": moon_buggy()
            elif clig.strip() == "06" or clig.strip() == "6": nudoku()
            elif clig.strip() == "07" or clig.strip() == "7": ttysolitaire()
            elif clig.strip() == "08" or clig.strip() == "8": pacman4console()
            elif clig.strip() == "00" or clig.strip() == "0": restart_program()
            else: print("\n错误:输入错误");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 17 - Malware Analysis
    elif lazymux.strip() == "17":
        print("\n    [01] Lynis：安全审计与Rootkit扫描工具")
        print("    [02] Chkrootkit：Linux系统Rootkit扫描工具")
        print("    [03] ClamAV：开源防病毒工具套件")
        print("    [04] Yara：恶意软件样本识别与分类工具")
        print("    [05] VirusTotal-CLI：VirusTotal平台的命令行交互工具")
        print("    [06] avpass：安卓恶意软件检测系统绕过与漏洞利用工具")
        print("    [07] DKMC：恶意Payload免杀工具")
        print("\n    [00] 返回主菜单\n")
        malsys = input("lzmx > set_install ")
        if malsys == "@":
            malsys = ""
            for x in range(1,201):
                malsys += f"{x} "
        if len(malsys.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for malx in malsys.split():
            if malx.strip() == "01" or malx.strip() == "1": lynis()
            elif malx.strip() == "02" or malx.strip() == "2": chkrootkit()
            elif malx.strip() == "03" or malx.strip() == "3": clamav()
            elif malx.strip() == "04" or malx.strip() == "4": yara()
            elif malx.strip() == "05" or malx.strip() == "5": virustotal()
            elif malx.strip() == "06" or malx.strip() == "6": avpass()
            elif malx.strip() == "07" or malx.strip() == "7": dkmc()
            elif malx.strip() == "00" or malx.strip() == "0": restart_program()
            else: print("\n错误:输入错误");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 18 - Compiler/Interpreter
    elif lazymux.strip() == "18":
        print("\n    [01] Python2：旨在实现清晰程序的Python")
        print("    [02] Eclipse Java编译器")
        print("    [03] Golang：Go编程语言编译器")
        print("    [04] ldc：基于LLVM构建的D编程语言编译器")
        print("    [05] Nim：Nim编程语言编译器")
        print("    [06] shc：Shell脚本编译器")
        print("    [07] TCC：小型C语言编译器（Tiny C Compiler）")
        print("    [08] PHP：服务器端嵌入式HTML脚本语言")
        print("    [09] Ruby：注重简洁性与开发效率的动态编程语言")
        print("    [10] Perl：功能丰富的编程语言")
        print("    [11] Vlang：简单、快速、安全的编译型语言，用于开发可维护软件")
        print("    [12] BeanShell：用Java编写的小型嵌入式Java源代码解释器（支持基于对象的脚本语言特性）")
        print("    [13] fp-compiler：Free Pascal编译器（支持32/64/16位专业Pascal开发）")
        print("    [14] Octave：科学计算编程语言")
        print("    [15] BlogC：博客内容编译器")
        print("    [16] Dart：通用型编程语言")
        print("    [17] Yasm：支持x86和AMD64指令集的汇编器")
        print("    [18] Nasm：跨平台x86汇编器（采用类Intel语法）")
        print("\n    [00] 返回主菜单\n")
        compter = input("lzmx > set_install ")
        if compter == "@":
            compter = ""
            for x in range(1,201):
                compter += f"{x} "
        if len(compter.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for compt in compter.split():
            if compt.strip() == "01" or compt.strip() == "1": python2()
            elif compt.strip() == "02" or compt.strip() == "2": ecj()
            elif compt.strip() == "03" or compt.strip() == "3": golang()
            elif compt.strip() == "04" or compt.strip() == "4": ldc()
            elif compt.strip() == "05" or compt.strip() == "5": nim()
            elif compt.strip() == "06" or compt.strip() == "6": shc()
            elif compt.strip() == "07" or compt.strip() == "7": tcc()
            elif compt.strip() == "08" or compt.strip() == "8": php()
            elif compt.strip() == "09" or compt.strip() == "9": ruby()
            elif compt.strip() == "10": perl()
            elif compt.strip() == "11": vlang()
            elif compt.strip() == "12": beanshell()
            elif compt.strip() == "13": fpcompiler()
            elif compt.strip() == "14": octave()
            elif compt.strip() == "15": blogc()
            elif compt.strip() == "16": dart()
            elif compt.strip() == "17": yasm()
            elif compt.strip() == "18": nasm()
            elif compt.strip() == "00" or compt.strip() == "0": restart_program()
            else: print("\n错误:输入错误");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 19 - Social Engineering Tools
    elif lazymux.strip() == "19":
        print("\n    [01] weeman：用Python编写的钓鱼HTTP服务器工具")
        print("    [02] SocialFish：教育et-online：社会工程学工具")
        print("    [03] santet-online：社会工程学工具")
        print("    [04] SpazSMS：向同一手机号重复发送骚扰短信的工具")
        print("    [05] LiteOTP：批量短信/OTP轰炸工具")
        print("    [06] F4K3：虚假用户数据生成工具")
        print("    [07] Hac：功能未明确的工具（名称可能为拼写错误或缩写）")
        print("    [08] Cookie-stealer：简易Cookie窃取工具")
        print("    [09] zphisher：自动化钓鱼工具")
        print("    [10] Evilginx：支持绕过双因素认证的高级钓鱼工具")
        print("    [11] ghost-phisher：从code.google.com迁移的自动钓鱼工具")
        print("\n    [00] 返回主菜单\n")
        soceng = input("lzmx > set_install ")
        if soceng == "@":
            soceng = ""
            for x in range(1,201):
                soceng += f"{x} "
        if len(soceng.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for socng in soceng.split():
            if socng.strip() == "01" or socng.strip() == "1": weeman()
            elif socng.strip() == "02" or socng.strip() == "2": socfish()
            elif socng.strip() == "03" or socng.strip() == "3": sanlen()
            elif socng.strip() == "04" or socng.strip() == "4": spazsms()
            elif socng.strip() == "05" or socng.strip() == "5": liteotp()
            elif socng.strip() == "06" or socng.strip() == "6": f4k3()
            elif socng.strip() == "07" or socng.strip() == "7": hac()
            elif socng.strip() == "08" or socng.strip() == "8": cookiestealer()
            elif socng.strip() == "09" or socng.strip() == "9": zphisher()
            elif socng.strip() == "10": evilginx()
            elif socng.strip() == "11": ghostphisher()
            elif socng.strip() == "00" or socng.strip() == "0": restart_program()
            else: print("\n错误:输入错误");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    elif lazymux.strip() == "99":
        os.system("git pull")
    elif lazymux.strip() == "0" or lazymux.strip() == "00":
        sys.exit()
    
    else:
        print("\n错误:输入错误")
        timeout(1)
        restart_program()

if __name__ == "__main__":
    os.system("clear")
    main()
