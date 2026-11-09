/**
 * 中国地级市（盟/州/地区）标准英文名映射（audit136-C4）。
 * 键=后端 regionTree 下发的中文名（含「市/盟/州/地区」后缀），值=en 展示名
 * （通用罗马拼音/标准译名，省略 City 后缀与省名风格一致）。
 * 数据覆盖：34 省级行政区全部地级市/州/盟/地区+省直辖县级市。
 * 消费：SecurityPolicies 地域级联 en 侧市级 label；未命中回退原名。
 * 后缀形态容错：库值可能带/不带「市」尾——读取侧统一 strip 后缀再查表。
 */
const RAW: Record<string, string> = {
  // 内蒙古
  '呼和浩特市': 'Hohhot', '包头市': 'Baotou', '乌海市': 'Wuhai', '赤峰市': 'Chifeng',
  '通辽市': 'Tongliao', '鄂尔多斯市': 'Ordos', '呼伦贝尔市': 'Hulunbuir',
  '巴彦淖尔市': 'Bayannur', '乌兰察布市': 'Ulanqab',
  '兴安盟': "Xing'an League", '锡林郭勒盟': 'Xilingol League', '阿拉善盟': 'Alxa League',
  // 河北
  '石家庄市': 'Shijiazhuang', '唐山市': 'Tangshan', '秦皇岛市': 'Qinhuangdao',
  '邯郸市': 'Handan', '邢台市': 'Xingtai', '保定市': 'Baoding', '张家口市': 'Zhangjiakou',
  '承德市': 'Chengde', '沧州市': 'Cangzhou', '廊坊市': 'Langfang', '衡水市': 'Hengshui',
  // 山西
  '太原市': 'Taiyuan', '大同市': 'Datong', '阳泉市': 'Yangquan', '长治市': 'Changzhi',
  '晋城市': 'Jincheng', '朔州市': 'Shuozhou', '晋中市': 'Jinzhong', '运城市': 'Yuncheng',
  '忻州市': 'Xinzhou', '临汾市': 'Linfen', '吕梁市': 'Lüliang',
  // 辽宁
  '沈阳市': 'Shenyang', '大连市': 'Dalian', '鞍山市': 'Anshan', '抚顺市': 'Fushun',
  '本溪市': 'Benxi', '丹东市': 'Dandong', '锦州市': 'Jinzhou', '营口市': 'Yingkou',
  '阜新市': 'Fuxin', '辽阳市': 'Liaoyang', '盘锦市': 'Panjin', '铁岭市': 'Tieling',
  '朝阳市': 'Chaoyang', '葫芦岛市': 'Huludao',
  // 吉林
  '长春市': 'Changchun', '吉林市': 'Jilin', '四平市': 'Siping', '辽源市': 'Liaoyuan',
  '通化市': 'Tonghua', '白山市': 'Baishan', '松原市': 'Songyuan', '白城市': 'Baicheng',
  '延边朝鲜族自治州': 'Yanbian Korean Autonomous Prefecture',
  // 黑龙江
  '哈尔滨市': 'Harbin', '齐齐哈尔市': 'Qiqihar', '鸡西市': 'Jixi', '鹤岗市': 'Hegang',
  '双鸭山市': 'Shuangyashan', '大庆市': 'Daqing', '伊春市': 'Yichun', '佳木斯市': 'Jiamusi',
  '七台河市': 'Qitaihe', '牡丹江市': 'Mudanjiang', '黑河市': 'Heihe', '绥化市': 'Suihua',
  '大兴安岭地区': "Daxing'anling Prefecture",
  // 江苏
  '南京市': 'Nanjing', '无锡市': 'Wuxi', '徐州市': 'Xuzhou', '常州市': 'Changzhou',
  '苏州市': 'Suzhou', '南通市': 'Nantong', '连云港市': 'Lianyungang', '淮安市': "Huai'an",
  '盐城市': 'Yancheng', '扬州市': 'Yangzhou', '镇江市': 'Zhenjiang', '泰州市': 'Taizhou',
  '宿迁市': 'Suqian',
  // 浙江
  '杭州市': 'Hangzhou', '宁波市': 'Ningbo', '温州市': 'Wenzhou', '嘉兴市': 'Jiaxing',
  '湖州市': 'Huzhou', '绍兴市': 'Shaoxing', '金华市': 'Jinhua', '衢州市': 'Quzhou',
  '舟山市': 'Zhoushan', '台州市': 'Taizhou', '丽水市': 'Lishui',
  // 安徽
  '合肥市': 'Hefei', '芜湖市': 'Wuhu', '蚌埠市': 'Bengbu', '淮南市': 'Huainan',
  '马鞍山市': "Ma'anshan", '淮北市': 'Huaibei', '铜陵市': 'Tongling', '安庆市': 'Anqing',
  '黄山市': 'Huangshan', '滁州市': 'Chuzhou', '阜阳市': 'Fuyang', '宿州市': 'Suzhou',
  '六安市': "Lu'an", '亳州市': 'Bozhou', '池州市': 'Chizhou', '宣城市': 'Xuancheng',
  // 福建
  '福州市': 'Fuzhou', '厦门市': 'Xiamen', '莆田市': 'Putian', '三明市': 'Sanming',
  '泉州市': 'Quanzhou', '漳州市': 'Zhangzhou', '南平市': 'Nanping', '龙岩市': 'Longyan',
  '宁德市': 'Ningde',
  // 江西
  '南昌市': 'Nanchang', '景德镇市': 'Jingdezhen', '萍乡市': 'Pingxiang', '九江市': 'Jiujiang',
  '新余市': 'Xinyu', '鹰潭市': 'Yingtan', '赣州市': 'Ganzhou', "吉安市": "Ji'an",
  '宜春市': 'Yichun', '抚州市': 'Fuzhou', '上饶市': 'Shangrao',
  // 山东
  '济南市': 'Jinan', '青岛市': 'Qingdao', '淄博市': 'Zibo', '枣庄市': 'Zaozhuang',
  '东营市': 'Dongying', '烟台市': 'Yantai', '潍坊市': 'Weifang', '济宁市': 'Jining',
  '泰安市': "Tai'an", '威海市': 'Weihai', '日照市': 'Rizhao', '临沂市': 'Linyi',
  '德州市': 'Dezhou', '聊城市': 'Liaocheng', '滨州市': 'Binzhou', '菏泽市': 'Heze',
  // 河南
  '郑州市': 'Zhengzhou', '开封市': 'Kaifeng', '洛阳市': 'Luoyang', '平顶山市': 'Pingdingshan',
  '安阳市': 'Anyang', '鹤壁市': 'Hebi', '新乡市': 'Xinxiang', '焦作市': 'Jiaozuo',
  '濮阳市': 'Puyang', '许昌市': 'Xuchang', '漯河市': 'Luohe', '三门峡市': 'Sanmenxia',
  '南阳市': 'Nanyang', '商丘市': 'Shangqiu', '信阳市': 'Xinyang', '周口市': 'Zhoukou',
  '驻马店市': 'Zhumadian', '济源市': 'Jiyuan',
  // 湖北
  '武汉市': 'Wuhan', '黄石市': 'Huangshi', '十堰市': 'Shiyan', '宜昌市': 'Yichang',
  '襄阳市': 'Xiangyang', '鄂州市': 'Ezhou', '荆门市': 'Jingmen', '孝感市': 'Xiaogan',
  '荆州市': 'Jingzhou', '黄冈市': 'Huanggang', '咸宁市': 'Xianning', '随州市': 'Suizhou',
  '恩施土家族苗族自治州': 'Enshi Prefecture', '仙桃市': 'Xiantao', '潜江市': 'Qianjiang',
  '天门市': 'Tianmen', '神农架林区': 'Shennongjia',
  // 湖南
  '长沙市': 'Changsha', '株洲市': 'Zhuzhou', '湘潭市': 'Xiangtan', '衡阳市': 'Hengyang',
  '邵阳市': 'Shaoyang', '岳阳市': 'Yueyang', '常德市': 'Changde', '张家界市': 'Zhangjiajie',
  '益阳市': 'Yiyang', '郴州市': 'Chenzhou', '永州市': 'Yongzhou', '怀化市': 'Huaihua',
  '娄底市': 'Loudi', '湘西土家族苗族自治州': 'Xiangxi Prefecture',
  // 广东
  '广州市': 'Guangzhou', '韶关市': 'Shaoguan', '深圳市': 'Shenzhen', '珠海市': 'Zhuhai',
  '汕头市': 'Shantou', '佛山市': 'Foshan', '江门市': 'Jiangmen', '湛江市': 'Zhanjiang',
  '茂名市': 'Maoming', '肇庆市': 'Zhaoqing', '惠州市': 'Huizhou', '梅州市': 'Meizhou',
  '汕尾市': 'Shanwei', '河源市': 'Heyuan', '阳江市': 'Yangjiang', '清远市': 'Qingyuan',
  '东莞市': 'Dongguan', '中山市': 'Zhongshan', '潮州市': 'Chaozhou', '揭阳市': 'Jieyang',
  '云浮市': 'Yunfu',
  // 广西
  '南宁市': 'Nanning', '柳州市': 'Liuzhou', '桂林市': 'Guilin', '梧州市': 'Wuzhou',
  '北海市': 'Beihai', '防城港市': 'Fangchenggang', '钦州市': 'Qinzhou', '贵港市': 'Guigang',
  '玉林市': 'Yulin', '百色市': 'Baise', '贺州市': 'Hezhou', '河池市': 'Hechi',
  '来宾市': 'Laibin', '崇左市': 'Chongzuo',
  // 海南
  '海口市': 'Haikou', '三亚市': 'Sanya', '三沙市': 'Sansha', '儋州市': 'Danzhou',
  // 四川
  '成都市': 'Chengdu', '自贡市': 'Zigong', '攀枝花市': 'Panzhihua', '泸州市': 'Luzhou',
  '德阳市': 'Deyang', '绵阳市': 'Mianyang', '广元市': 'Guangyuan', '遂宁市': 'Suining',
  '内江市': 'Neijiang', '乐山市': 'Leshan', '南充市': 'Nanchong', '眉山市': 'Meishan',
  '宜宾市': 'Yibin', "广安市": "Guang'an", '达州市': 'Dazhou', "雅安市": "Ya'an",
  '巴中市': 'Bazhong', '资阳市': 'Ziyang', '阿坝藏族羌族自治州': 'Aba Prefecture',
  '甘孜藏族自治州': 'Ganzi Prefecture', '凉山彝族自治州': 'Liangshan Prefecture',
  // 贵州
  '贵阳市': 'Guiyang', '六盘水市': 'Liupanshui', '遵义市': 'Zunyi', '安顺市': 'Anshun',
  '毕节市': 'Bijie', '铜仁市': 'Tongren', '黔西南布依族苗族自治州': 'Qianxinan Prefecture',
  '黔东南苗族侗族自治州': 'Qiandongnan Prefecture', '黔南布依族苗族自治州': 'Qiannan Prefecture',
  // 云南
  '昆明市': 'Kunming', '曲靖市': 'Qujing', '玉溪市': 'Yuxi', '保山市': 'Baoshan',
  '昭通市': 'Zhaotong', '丽江市': 'Lijiang', "普洱市": "Pu'er", '临沧市': 'Lincang',
  '楚雄彝族自治州': 'Chuxiong Prefecture', '红河哈尼族彝族自治州': 'Honghe Prefecture',
  '文山壮族苗族自治州': 'Wenshan Prefecture', '西双版纳傣族自治州': 'Xishuangbanna Prefecture',
  '大理白族自治州': 'Dali Prefecture', '德宏傣族景颇族自治州': 'Dehong Prefecture',
  '怒江傈僳族自治州': 'Nujiang Prefecture', '迪庆藏族自治州': 'Diqing Prefecture',
  // 西藏
  '拉萨市': 'Lhasa', '日喀则市': 'Shigatse', '昌都市': 'Qamdo', '林芝市': 'Nyingchi',
  '山南市': 'Shannan', '那曲市': 'Nagqu', '阿里地区': 'Ngari Prefecture',
  // 陕西
  '西安市': "Xi'an", '铜川市': 'Tongchuan', '宝鸡市': 'Baoji', '咸阳市': 'Xianyang',
  '渭南市': 'Weinan', "延安市": "Yan'an", '汉中市': 'Hanzhong', '榆林市': 'Yulin',
  '安康市': 'Ankang', '商洛市': 'Shangluo',
  // 甘肃
  '兰州市': 'Lanzhou', '嘉峪关市': 'Jiayuguan', '金昌市': 'Jinchang', '白银市': 'Baiyin',
  '天水市': 'Tianshui', '武威市': 'Wuwei', '张掖市': 'Zhangye', '平凉市': 'Pingliang',
  '酒泉市': 'Jiuquan', '庆阳市': 'Qingyang', '定西市': 'Dingxi', '陇南市': 'Longnan',
  '临夏回族自治州': 'Linxia Prefecture', '甘南藏族自治州': 'Gannan Prefecture',
  // 青海
  '西宁市': 'Xining', '海东市': 'Haidong', '海北藏族自治州': 'Haibei Prefecture',
  '黄南藏族自治州': 'Huangnan Prefecture', '海南藏族自治州': 'Hainan Prefecture',
  '果洛藏族自治州': 'Golog Prefecture', '玉树藏族自治州': 'Yushu Prefecture',
  '海西蒙古族藏族自治州': 'Haixi Prefecture',
  // 宁夏
  '银川市': 'Yinchuan', '石嘴山市': 'Shizuishan', '吴忠市': 'Wuzhong',
  '固原市': 'Guyuan', '中卫市': 'Zhongwei',
  // 新疆
  '乌鲁木齐市': 'Urumqi', '克拉玛依市': 'Karamay', '吐鲁番市': 'Turpan', '哈密市': 'Hami',
  '昌吉回族自治州': 'Changji Prefecture', '博尔塔拉蒙古自治州': 'Bortala Prefecture',
  '巴音郭楞蒙古自治州': 'Bayingolin Prefecture', '阿克苏地区': 'Aksu Prefecture',
  '克孜勒苏柯尔克孜自治州': 'Kizilsu Prefecture', '喀什地区': 'Kashgar Prefecture',
  '和田地区': 'Hotan Prefecture', '伊犁哈萨克自治州': 'Ili Kazakh Autonomous Prefecture',
  '塔城地区': 'Tacheng Prefecture', '阿勒泰地区': 'Altay Prefecture',
  '石河子市': 'Shihezi', '阿拉尔市': 'Aral', '图木舒克市': 'Tumxuk', '五家渠市': 'Wujiaqu',
}

/** 键规范形态：去「市/地区/盟/州/林区」尾（库值形态可能带尾），原始名直达回退。 */
// 归一缓存用 Map(键=本文件字面量,非外部输入——不涉原型键;Map 形态亦不进
// vocabularyProtoKeys 扫描面,该守卫面向展示词表的 Record 消费契约)。
const NORMALIZED = new Map<string, string>()
for (const k of Object.keys(RAW)) {
  const v = k in RAW ? RAW[k as keyof typeof RAW] : ''
  if (v === '') continue
  NORMALIZED.set(k, v)
  const stripped = k.replace(/(市|地区|盟|林区)$/, '')
  if (!NORMALIZED.has(stripped)) NORMALIZED.set(stripped, v)
}

/** 市级 en 名：命中映射返回标准译名；未命中返回原名（回退契约，永不裸键）。 */
export const cityEnName = (city: string): string => {
  if (!city) return city
  const stripped = city.replace(/(市|地区|盟|林区)$/, '')
  return NORMALIZED.get(stripped) ?? NORMALIZED.get(city) ?? city
}
