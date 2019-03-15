#coding=utf-8

import sys
import requests,time
import re
import os

sys.path.append(sys.path[0]+'\\tools')

from port_scan import C_scan
from sensitive_dir import dir_search
from subdomain_search import subdomain_search
from sensitive_dir import dir_search
from dns_transport import dns_transport
from put_or_delet import put_or_delet
from sql import find_sql_inject
from XSS import find_xss
from ssrf import find_ssrf
from url_jump import url_jump
from heart_bleed import heart_bleed

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)             #这两行是为了防止https报错

spider_alreadyliste=[]          #已经爬行过的url
get_request=[]
post_request=[]
patter_picture_etc = '[\.]+(jpg|png|jpeg|css|js|ico|wmv|mp3|mp4|bmp|svg|cert|gif|tif|zip|pdf|exe|apk)+[\?]?'  # 显然图片或者其他的连接没有意义

headers = {
    'Content-Type':"application/x-www-form-urlencoded",
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.71 Safari/537.36'
}
cookies = {
}

def spider_url(url,submit_method,data):          #从某个页面开始爬行，递归爬行，注意，为了防止被封ip，每次爬行后暂停1秒（反正时间多得是）
    print "正在爬取    "+url
    write_file('发现    '+url+'  '+submit_method+'  类型  '+'\n')
    time.sleep(0.5)            #防止过快

    if submit_method=='get':
        response=spider_get(url)
    else:
        response=spider_post(url,data)
    if response!='false':
        gain_get(url, response.content)
        gain_post(url,response.content)
    return

def gain_post(url,content):                     #得到内容内，所有post类型的表单（由于post请求的灵活性，一定会有遗漏的），并进行递归
    server = re.findall('(^http(s)?:\/\/[\w\.\-:]+)', url)[0][0]  # 服务器名，用于拼接可能存在的相对地址
    patterns_form = '<form[\S\s]+method="post[\s\S]+action=[\s\S]+</form>' # 找到页面内所有连接的post表单
    post_forms=re.findall(patterns_form,content)
    pattern_action='action=[\"\']?[\w\./\:\-#?=%&]+[\"\']?'                   #post表单的提交地址
    pattern_parameter='name=\"[\w]+\"'                                    #post请求的参数

    for form in post_forms:
        action=re.findall(pattern_action,form)
        parameters=re.findall(pattern_parameter,form)
        if len(action)>1:
            print '可能有什么地方出错了，检测到多余一个的post请求的action'
            continue
        action=action[0].replace('action=','').replace('"','').replace("'","")
        if not((server+'/'+action) in spider_alreadyliste):
            spider_alreadyliste.append(server+'/'+action)
            para_list=[]                        #保存post请求的body参数
            for parameter in parameters:
                para_list.append(parameter.replace('name','').replace('=','').replace('"',''))
            body={}                           #一个字典
            for p in para_list:
                body[p]='1'               #提交每个参数的值，存入body
            spider_url(server+'/'+action,'post',body)               #发送post请求
    return



def gain_get(url,content):                       #得到内容内，所有get型请求，并进行递归
    patterns_links='href=\"[\w\./\:\-#?=%&]+\"'                 #找到页面内所有连接的表达式
    links=re.findall(patterns_links,content)
    get_url_list=[]
    spider_alreadyliste.append(url)             #将网址添加到已爬行列表
    for link in links:
        link=link.replace('"','')
        if len(re.findall(patter_picture_etc,link))==0:            #并不是图片...等等
            get_url_list.append(link.replace('href=',''))

    server=re.findall('(^http(s)?:\/\/[\w\.\-:]+)',url)[0][0]     #服务器名，用于拼接可能存在的相对地址

    for l in get_url_list:
        if len(re.findall('^http',l))==0:          #如果是一个相对地址
            if not((server+'/'+l) in spider_alreadyliste):        #如果以前没有爬过
                spider_url(server+'/'+l,'get','')
        else:                                      #如果是一个绝对地址或ip
            if not(l in spider_alreadyliste):        #如果以前没有爬过
                in_white_list=0                #检测是否在白名单中，也就是之前是否曾经爬取过
                for ll in spider_whitelist:
                    if len(re.findall('https?://[\w\.-]*.'+ll,l)):     #如果检测到白名单中有这个服务器名
                        in_white_list=1
                        continue
                if in_white_list==0:
                    print "发现新域名  "+l+"  如果需要爬取就将其加入白名单"
                    spider_alreadyliste.append(l)
                else:                         #在白名单中
                    spider_url(l,"get",'')

    return

def spider_get(url):                               #发送get请求
    get_request.append(url)
    try:                   #有一些可能是死链接
        response = requests.get(url=url,headers=headers, timeout=5, allow_redirects=True, verify=False,cookies=cookies)
        response.close()
        return response
    except requests.ConnectTimeout as e:
        print url+'   '+str(e)
        return 'false'
    except requests.ConnectionError as e:
        print url+'   '+str(e)
        return 'false'
    except requests.ReadTimeout as e:
        print url+'   '+str(e)
        return 'false'

def spider_post(url,data):                         #发送post请求
    r_data=''                                               # request中的data应该是一个字典，但是这里将data转为string保存，为了传递方便
    for d in data:
        r_data=r_data+d+'='+data[d]+'&'

    p_data=[url,r_data[:-1]]            #去掉最后一个&
    post_request.append(p_data)
    try:                   #有一些可能是死链接
        response = requests.post(url=url,data=data,headers=headers, timeout=5, allow_redirects=True, verify=False,cookies=cookies)
        response.close()
        return response
    except requests.ConnectTimeout as e:
        print url+'   '+str(e)
        return 'false'
    except requests.ConnectionError as e:
        print url+'   '+str(e)
        return 'false'
    except requests.ReadTimeout as e:
        print url+'   '+str(e)
        return 'false'

def write_file(content):         #将内容写到文件
    if not os.path.exists("./result/"):  # 输出文件
        os.makedirs("./result/")
    f = open('./result/spider_results.txt', 'a')
    f.write(content)
    f.close()

def main_spider(url):         #主爬虫，用于传递最开始页面的返回信息
    try:                   #有一些可能是死链接
        spider_url(url,"get",'')
        print spider_alreadyliste
        return
    except requests.ConnectTimeout as e:
        print url+'   '+str(e)
        return
    except requests.ConnectionError as e:
        print url+'   '+str(e)
        return
    except requests.ReadTimeout as e:
        print url+'   '+str(e)
        return



if __name__=="__main__":
    #spider_whitelist = ['microtek.com.cn']  # 这个白名单指允许爬行的域名（比如baidu.com），只有存在的域名才会继续爬行

    #print url_jump("http://91baby.mama.cn/api/img/wapimg.php?img=http://www.baidu.com")
    #for i in range(3,255):
    #C_scan("113.31."+str(i)+'.1')
    #print C_scan("140.207.228.6")
    #print subdomain_search("zbj.com")
    #dns_transport("bocichina.com")
    #main_spider("http://www.mh-rjgb.com:7007/")
    #print spider_alreadyliste
    #dir_search("http://xsc.cuc.edu.cn/")
    #spider_url("https://hr.tencent.com","get","")
    #heart_bleed("27.223.70.24",443)
    #main_spider("http://www.microtek.com.cn/")
    #for i in get_request:
    #    find_sql_inject(i,'get','')
    #    find_xss(i,'get','')
    #    time.sleep(0.5)
    #for i in post_request:
    #    find_sql_inject(i[0],'post',i[1])
    #    time.sleep(0.5)

    test=[
        "https://is-neitui-dev.corp.kuaishou.com/recruit/#/internal/",
    ]
for t in test:
    dir_search(t)