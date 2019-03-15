#coding=utf-8
import requests,time
import re
import ssl
import os

#该脚本用于检测url跳转漏洞，使用了@进行简单的绕过

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)             #这两行是为了防止https报错

def url_jump(url):
    if url.find('?')==-1:       #如果不存在?则可能url中并不存在参数
        print "不存在参数"
        return
    pattern_gethost = '([\w|//|.|:|-]*\?)'          #得到host的正则表达式（host指除了参数的其他部分，不是传统的host。这个我不知道叫啥）
    host = re.findall(pattern_gethost, url)[0].replace('?','')
    get_param_temp=url.replace(host,'')[1:]
    params=get_param_temp.split('&')

    dict={}                          #一个字典，key是参数名，value是参数的值
    for p in params:
        loc=p.index('=')
        key=p[0:loc]
        value=p[loc+1:]
        dict[key] = value

    pattern_domain = '(^http[s]{0,1}://[\w.]+)'
    domain = re.findall(pattern_domain, host)[0]

    headers = {
        'Content-Type':"application/x-www-form-urlencoded",
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.71 Safari/537.36'
    }
    rest = requests.get(url=url, headers=headers, timeout=1, allow_redirects=False, verify=False)
    if rest.status_code == 302 or rest.status_code == 301:  # 如果网页存在重定向功能
        if not os.path.exists("./result/"):       #输出文件，注意，由于我们最终是在main_spider中调用这个函数，因此这里的地址指的是相对于main_spider.py的位置
            os.makedirs("./result/")
        f = open('./result/url_jump.txt', 'a')
        f.write(url+'存在重定向功能，请人工确认\n')
        print url+'存在重定向功能，请人工确认'
        rest.close()
    else:
        rest.close()
        return "似乎没有url跳转"

    for d in dict:
        f.write('检测'+d+'\n')
        f.write('正在检测参数'+d+'\n')
        print '检测'+d
        print '正在检测参数'+d
        testurl=url.replace(d+'='+dict[d],d+'='+domain+'@www.baidu.com')              #利用@进行一个简单绕过
        rest = requests.get(url=testurl, headers=headers, timeout=1,verify=False)
        if "//www.baidu.com/img/baidu_85beaf5496f291521eb75ba38eacbd87.svg" in rest.text:  # 是否存在url跳转漏洞的判断标准，前者是百度首页的一个元素
             f.write('参数 ' + d + ' 可能存在url跳转漏洞（可能需@绕过）\n')
             print '参数 ' + d + ' 可能存在url跳转漏洞（可能需@绕过）'
             rest.close()
             continue
        rest.close()
    f.close()
    return "over"

#一个存在url跳转的网址http://91baby.mama.cn/api/img/wapimg.php?img=http://www.baidu.com
#url_jump("https://hr.yylending.com/theme/default?url=https://www.baidu.com")    #我觉得最后可能是需要从文件读取或者其他脚本调用，不过先这样吧