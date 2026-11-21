"""生成大样本良性集（用于量化误伤率 FP）。

思路：手工维护"业务主域"基座（品牌官网/政务/银行/医院/学校…，都是确定不属于广告的域），
再叠加常见子域前缀（www / m / app / api / static），最后做 DNS 存在性校验——
校验不过的直接丢弃，保证样本里没有我编错的假域。

产物：tests/benign_5000.txt
"""
import concurrent.futures as cf
import pathlib
import socket
import sys

PREFIXES = ["", "www.", "m.", "app.", "api.", "static.", "h5.", "wap.", "cdn.", "open.", "pay.", "passport.", "im.", "live.", "news.", "video.", "img.", "assets.", "service.", "account."]

BASES = """
# 门户 / 资讯
qq.com sina.com.cn sina.com sohu.com 163.com netease.com ifeng.com thepaper.cn
people.com.cn xinhuanet.com chinanews.com cctv.com cctv.cn cnr.cn gmw.cn
china.com.cn chinadaily.com.cn yicai.com caixin.com cls.cn eastmoney.com
hexun.com jiemian.com 36kr.com tmtpost.com huxiu.com ithome.com zol.com.cn
pconline.com.cn yesky.com techweb.com.cn donews.com cnbeta.com solidot.org
leiphone.com pingwest.com geekpark.net ifanr.com sspai.com qdaily.com
# 视频 / 音频 / 直播
bilibili.com iqiyi.com youku.com tudou.com mgtv.com v.qq.com
migu.cn miguvideo.com wasu.cn letv.com acfun.cn huya.com douyu.com
yy.com kuaishou.com douyin.com ixigua.com xigua.com
music.163.com y.qq.com kugou.com kuwo.cn xiami.com qingting.fm lizhi.fm
ximalaya.com lazyaudio.com desstv.com
# 社交 / 社区
weibo.com weibo.cn zhihu.com douban.com tieba.baidu.com renren.com
kaixin001.com tianya.cn hupu.com longhoo.net v2ex.com jianshu.com
xiaohongshu.com xhscdn.com moment.zxxk.com wechat.com weixin.qq.com
# 电商 / 支付 / 物流
taobao.com tmall.com jd.com pinduoduo.com vip.com suning.com
gome.com.cn dangdang.com yhd.com jumei.com mogujie.com you.163.com
kaola.com sephora.cn womai.cn yiguo.com meicai.cn
alipay.com 95516.com tenpay.com unionpay.com paypal.com
sf-express.com sto.cn yundaex.com ems.com.cn zto.com jtexpress.cn
ytoexpress.com debangwuliu.com annengwl.com 58.com ganji.com
zhuanzhuan.com xianyu.taobao.com ai.taobao.com
# 出行 / 地图 / 酒店 / 旅游
amap.com baidu.com ditu.baidu.com maps.google.com
didiglobal.com didi.com ucarr.com caocao.com t3go.cn
ctrip.com qunar.com ly.com 17u.cn tuniu.com mafengwo.cn lvmama.com
fliggy.com hotels.taobao.com air.taobao.com
12306.cn ctripcorp.com railway.com.cn
# 本地生活 / 外卖 / 团购
meituan.com dianping.com ele.me waimai.meituan.com meituan.net
nuomi.com kaidian.meituan.com
# 内容 / 阅读 / 出版
qidian.com zongheng.com 17k.com jjwxc.net readnovel.com
xiaoshuo.qq.com weread.qq.com duokan.com weibo.com
# 教育 / 学术
xueersi.com zuoyebang.com yuanfudao.com 100tal.com bytedance.com
coursera.org edx.org icourse163.org netease.study.163.com
cnki.net wanfangdata.com.cn cqvip.com douban.com
pku.edu.cn tsinghua.edu.cn fudan.edu.cn sjtu.edu.cn zju.edu.cn
ustc.edu.cn nju.edu.cn whu.edu.cn hit.edu.cn buaa.edu.cn
# 政务 / 公共
gov.cn beijing.gov.cn shanghai.gov.cn gd.gov.cn zj.gov.cn js.gov.cn
sd.gov.cn henan.gov.cn hubei.gov.cn sc.gov.cn cq.gov.cn tj.gov.cn
12345.gov.cn chinatax.gov.cn customs.gov.cn mohrss.gov.cn nhc.gov.cn
moe.gov.cn most.gov.cn miit.gov.cn mof.gov.cn stats.gov.cn
12315.cn samr.gov.cn nmpa.gov.cn ybj.gov.cn
# 银行 / 金融
icbc.com.cn ccb.com abchina.com boc.cn bankcomm.com cmbchina.com
psbc.com spdb.com.cn cib.com.cn citicbank.com cebbank.com hxb.com.cn
pingan.com pingan.com.cn bank.pingan.com
ccb.com.cn cgbchina.com.cn boc.com.cn cmbc.com.cn
hsbc.com.cn ctf.com.cn
# 保险 / 证券 / 基金
e-chinalife.com picc.com.cn cpic.com.cn tpl.com.cn
htsc.com.cn citics.com citic.com.cn swhy.com.cn
eastmoney.com xueqiu.com jrj.com.cn hexun.com fund.eastmoney.com
# 运营商 / 通信
10086.cn chinaunicom.com.cn chinatelecom.com.cn cmcc.com
189.cn cndns.com dnspod.cn dns.alidns.com aliDNS.com
# 医院 / 健康
haodf.com dxy.cn guahao.com 120ask.com chunyuyisheng.com
medlive.cn yy.com human.com
# 招聘 / 职场
zhaopin.com 51job.com liepin.com lagou.com bosszhipin.com
maimai.cn kanzhun.com jobui.com
# 汽车 / 房产 / 家居
autohome.com.cn pcauto.com.cn yiche.com dongchedi.com
lianjia.com ke.com fang.com soufun.com anjuke.com 5i5j.com
mtime.com ikea.cn tbcdn.cn
# 工具 / 输入法 / 下载
wps.cn wps.com kingsoft.com sogou.com sogou.com.cn
baidu.com pinyin.sogou.com shurufa.baidu.com
xunlei.com qq.pcmgr.qq.com pcmgr.qq.com cdn.baidu.com
360.cn 360.com 360doc.com 360safe.com 360kan.com
# 云服务 / 开发者
aliyun.com aliyuncs.com tencentcloud.com huaweicloud.com
cloud.baidu.com qcloud.com volcengine.com
github.com gitlab.com gitee.com coding.net
csdn.net cnblogs.com oschina.net segmentfault.com
juejin.cn infoq.cn developer.aliyun.com 51cto.com
# 电商服务 / 企业
alibaba.com alibaba.cn 1688.com aliexpress.com
weixin.qq.com mp.weixin.qq.com open.weixin.qq.com
work.weixin.qq.com
feishu.cn larksuite.com dingtalk.com
qiyewx.com
# 游戏
163.com netease.com blizzard.cn mihoyo.com hoyoverse.com
tencent.com game.qq.com pg.qq.com
4399.com 37.com 9game.cn
# 省级政务
hebei.gov.cn shanxi.gov.cn ln.gov.cn jl.gov.cn hlj.gov.cn jiangsu.gov.cn
ah.gov.cn fj.gov.cn jx.gov.cn ha.gov.cn hunan.gov.cn hain.gov.cn
gxzf.gov.cn yn.gov.cn gz.gov.cn gsq.gov.cn xizang.gov.cn sx.gov.cn
nx.gov.cn xj.gov.cn bj.gov.cn
# 高校补充
ruc.edu.cn cau.edu.cn bnu.edu.cn bupt.edu.cn bit.edu.cn tju.edu.cn
nankai.edu.cn seu.edu.cn tongji.edu.cn ecnu.edu.cn hdu.edu.cn
scu.edu.cn swjtu.edu.cn xmu.edu.cn fzu.edu.cn jnu.edu.cn
sysu.edu.cn scut.edu.cn hust.edu.cn whut.edu.cn csu.edu.cn
lzu.edu.cn xjtu.edu.cn dlut.edu.cn neu.edu.cn jlu.edu.cn
# 医院
pumch.cn wchscu.cn dyyy.com.cn 301hospital.com.cn bjtrhos.com
renji.com srrsh.com fsyyy.com zs-hospital.com
# 连锁零售 / 餐饮
yumchina.com kfc.com.cn mcdonalds.com.cn starbucks.com.cn
walmart.cn yonghui.com.cn rt-mart.com.cn hema.com
luckincoffee.com heytea.com naixue.com cotti.cn
# 快消 / 服饰
nike.com.cn adidas.com.cn uniqlo.cn zara.cn hm.com.cn
li-ning.com.cn anta.com.cn xtep.com.cn
# 汽车
byd.com geely.com changan.com.cn gwm.com.cn saic.com.cn
bwm.com.cn bmw.com.cn mercedes-benz.com.cn audi.com.cn
toyota.com.cn honda.com.cn nissan.com.cn mazda.com.cn
volkswagen.com.cn tesla.cn nio.com xpeng.com li-auto.com
# 3C / 家电
haier.com midea.com gree.com hisense.com tcl.com
skyworth.com robam.com joyoung.com supor.com
# 云盘 / 网盘
pan.baidu.com aliyunpan.com 115.com quark.cn caiyun.139.com
123pan.com
# 浏览器 / 输入法 / 安全
chrome.google.com firefox.com microsoftedge.microsoft.com
2345.com liebao.cn ucbrowser.cn qb.qq.com
iflytek.com mail.163.com mail.126.com mail.qq.com mail.sina.com.cn
mail.aliyun.com
# 游戏补充
17173.com gamelook.com gameres.com gamedog.cn
# 小说补充
tom365.com 69shu.com bxwx.la
# 地方媒体
bjnews.com.cn xhby.net yunnan.cn hunantv.com jiangxi.net
southen.com nanfangdaily.com.cn cqnews.net sxdaily.com.cn
# SaaS / 办公 / 企业服务
tezign.com sensetime.com megvii.com yonyou.com kingdee.com
chanjet.com seeyon.com fenghuang.com
# 医疗健康
dxy.com chunyuyisheng.com medsci.cn yiyaojd.com
# OTA / 酒店集团
huazhu.com joy-hotels.com homeinns.com
# 免税 / 奢侈品
ctg.com.cn dfss.com.cn
# 快递 / 物流补充
ems.cn jdwl.cn yundaex.com.cn suguo.com jingdongwl.com
# 本地生活补充
meituan.com.cn dianping.com.cn ele.me.cn
# 公共事业 / 缴费
95598.cn sgcc.com.cn csg.cn waterchina.com
# 母婴 / 宠物 / 家装 / 婚恋
mama.cn babytree.com ci123.com boqii.com chongwuxiu.com
home.163.com jianyu.com jiaren.org
zhenai.com jiayuan.com baihe.com
# 县域 / 城市服务
csdn.net city.qq.com
# 银行子品牌 / 信用卡
creditcard.ccb.com lufax.com 9fgroup.com jdpay.com
# 支付补充
tenpay.com cft.qq.com
# 视频补充
mgtv.com.cn sohu.com.cn pptv.com pptv.cn besTV.com
# 音乐补充
music.douyin.com music.kugou.com
# 网盘补充
drive.google.com dropbox.com onedrive.live.com pan.quark.cn
# 出行补充
hellobike.com mobike.com qingju.com
# 汽车服务
tuhu.cn che168.com guazi.com renrenche.com
# 旅游补充
trip.com booking.com airbnb.cn
# 招聘补充
doumi.com shixiseng.com yingjiesheng.com
# 电商补充
tao.163.com youpin.mi.com miyoupin.com
# 开发者补充
npmjs.com pypi.org rubygems.org docker.com
# 通讯 / 邮箱补充
foxmail.com 139.com 189.cn webmail.qq.com
# 安全 / 反诈
96110.cn 12321.cn
# 其他常用
apple.com.cn apple.com microsoft.com office.com
vivo.com oppo.com mi.com xiaomi.com huawei.com honor.com
realme.com meizu.com oneplus.com lenovo.com.cn lenovo.com
dell.com hp.com asus.com.cn acer.com.cn
jd.com vip.com tmall.com
12306.cn airchina.com.cn csair.com cnair.com
icloud.com
"""


def domains():
    out = []
    for line in BASES.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out += [p.strip() for p in line.split() if p.strip()]
    return out


def alive(d):
    for fam in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.setdefaulttimeout(3)
            socket.getaddrinfo(d, None, fam, socket.SOCK_STREAM)
            return True
        except Exception:
            continue
    return False


def main():
    bases = sorted({d for d in domains()})
    cand = []
    for b in bases:
        for p in PREFIXES:
            cand.append(p + b)
    print(f"候选 {len(cand)}（基座 {len(bases)}）")

    ok = []
    with cf.ThreadPoolExecutor(max_workers=64) as ex:
        for d, res in zip(cand, ex.map(alive, cand)):
            if res:
                ok.append(d)
    print(f"可解析 {len(ok)}")

    # 合并已有良性资产
    extra = []
    for f in ("tests/benign_baseline.txt", "lists/benign_top.txt", "lists/service_allow.txt"):
        p = pathlib.Path(f)
        if p.exists():
            extra += [l.strip() for l in p.read_text(encoding="utf-8").splitlines()
                      if l.strip() and not l.startswith("#")]
    result = sorted(set(ok) | set(extra))

    head = [
        "# 大样本良性集（用于量化误伤率 FP）",
        "# 生成：tools/benign_gen.py —— 业务主域基座 × 常见子域前缀，且必须 DNS 可解析",
        f"# 基座 {len(bases)} 个，候选 {len(cand)}，可解析 {len(ok)}，含手工资产共 {len(result)} 条",
        "# 注意：故意不剔除已在规则集命中的域 —— 命中就是误伤，必须被看见",
    ]
    pathlib.Path("tests/benign_5000.txt").write_text("\n".join(head + result) + "\n", encoding="utf-8")
    print(f"写出 tests/benign_5000.txt：{len(result)} 条")
    return 0 if len(result) >= 3000 else 1


if __name__ == "__main__":
    sys.exit(main())
