from getgauge.python import step, before_scenario, data_store,Messages
from zapv2 import ZAPv2 as ZAP
from time import sleep
import requests
import subprocess
import os
import datetime

port = '9090'
# zap_proxies = {"http":"http://127.0.0.1:{0}".format(port),"https":"https://127.0.0.1:{0}.format(port)"}
zap_proxies = {"http":"http://127.0.0.1:9090","https":"https://127.0.0.1:9090"}
zap = ZAP(proxies=zap_proxies)

print('hello')

@step("Start ZAP")
def start_zap():
    # cmd = "/Applications/OWASP_ZAP.app/Contents/Java/zap.sh -daemon -config api.disablekey=true -port {0}".format(port)
    cmd = "/Applications/OWASP_ZAP.app/Contents/Java/zap.sh -daemon -config api.disablekey=true -port 9090"

    subprocess.Popen(cmd.split(" "),stdout=open(os.devnull, "w"))

    while True:
        try:
            # status_req = requests.get("http://127.0.0.1:{0}".format(port))
            status_req = requests.get("http://127.0.0.1:9090")
            print(status_req)
            if status_req.status_code == 200:
                break
            else:
                print("zap is starting")
                sleep(1)
            pass
        except Exception:
            print("waiting zap to start")
            sleep(5)
            pass
    # 新建一个zap session,把要测试的目标应用程序的base url添加到context中
    zap.core.new_session(name="New Default Session",overwrite=True)
    zap.context.include_in_context("Default Context","https://marcia-dynamic-security-auto.herokuapp.com.*")
    print("zap is running now")


@step("Visit login page")
def visit_login():
    login_url = "https://marcia-dynamic-security-auto.herokuapp.com/login#/"
    # 发送给juice shop的请求都需要经过zap代理
    # verify = False 不去检查服务器证书是否正确（为使zap能成功解析https,提前本地安装并信任zap的网络证书）
    requests.get(login_url, proxies = zap_proxies, verify = False)


@step("Login as user <username> with password <password>")
def login(username,password):
    url = "https://marcia-dynamic-security-auto.herokuapp.com/login#/"
    login_data = {"email":username, "password":password}
    login = requests.post(url, proxies = zap_proxies, json = login_data, verify = False)
    print(login.json)
    if login.status_code == 200:
        resp_json = login.json
        print(resp_json)
        # auth_token = resp_json['authentication']['token']
        # data_store.spec.auth_token = auth_token
    else:
        print("unable to login")
        raise Exception ("unable to login")


# zap主动爬取服务器参数
@step("Perform spider from <url>")
def zap_spider(url):
    spider_id = zap.spider.scan(url,recurse = False, subtreeonly = True)
    data_store.spec.spider_id = spider_id


# 查看zap的爬取进度（zap爬取api很慢）
@step("Get spider status")
def zap_spider_status():
    status = 0
    while int(status) < 100:
        status = zap.spider.status(data_store.spec.spider_id)
        print('spider status is:' + status)
        sleep(1)

# 爬取完成后，zap进行主动模式安全扫描
@step("Perform zap active scan against <target_url>")
def zap_active_scan(target_url):
    scan_id = zap.ascan.scan(target_url,recurse = False, inscopeonly = True)
    data_store.spec.scan_id = scan_id

# 通过scan_id查看当前安全扫描的进度
@step("Get active scan status")
def zap_get_active_status():
    scan_status = 0
    while int(scan_status) < 100:
        scan_status = zap.ascan.status(data_store.spec.scan_id)
        print('active scanning {0}%'.format(scan_status))
        sleep(1)

# 查看整个测试过程中，在目标程序中发现的所有安全问题的汇总信息
@step("Get alerts summary")
def zap_alerts_summary():
    url = "https://marcia-dynamic-security-auto.herokuapp.com"
    summary = zap.alert.alerts_summary(url)
    print('Alerts summary: {0}'.format(summary))


# 生成测试报告
@step("Save scan report to <file_path>")
def zap_scan_report(file_path):
    report = zap.core.htmlreport()
    with open(file_path,'w') as file:
        file.write(report)
        print("report saved to {0}".format(file_path))

# 关闭zap
@step("Shutdown ZAP")
def zap_shutdown():
    zap.core.shutdown()
