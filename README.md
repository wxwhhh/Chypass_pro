# Chypass_pro

> 一个基于 AI 自动绕过 WAF、完成 XSS 漏洞测试的 Burp Suite 扩展
> 
> 插件已升级到Chypass_pro2.0版本，针对1.0出现的很多bug及其问题，对Chypass_pro进行了升级。
---
**郑重声明：文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途以及盈利等目的，否则后果自负**
## 工具简介

看 GitHub 上发现一个好玩的工具，用 AI 自动绕过 WAF 完成 XSS 漏洞测试。经过编译后，我感觉效果略有不足且存在一些小 bug，所以对原项目进行了二次开发（造轮子），优化了代码和 AI 交互词，完善了功能。为此，我将其命名为Chypass_pro。

原项目地址：https://aizhuanqian.com

---

## 工具安装配置

### 工具介绍

Chypass_pro 调用 AI 自动化生成绕过 WAF 的 XSS payload。  
本项目提供了两种打包格式：  
- **Java 8 版本**（适用于低版本 Burp 用户）  
- **Java 11+ 版本**
请根据你的环境选择对应版本进行下载和使用。

### 安装步骤

1. **下载插件**  
   下载对应的 jar 包（Java 8 或 Java 11 版本）。
![image](https://github.com/user-attachments/assets/396d0a13-8b15-4c59-805c-f8aab8d96600)


2. **导入插件**  
   在 Burp Suite 中选择 **Extender** → **Extensions**，点击 **Add**，选择 **Java** 类型，然后加载你下载的 jar 文件。![image](https://github.com/user-attachments/assets/0635a147-0123-4ac6-8a53-7a33c60a3317)


3. **配置 API Key**  
   导入插件后，请先配置 AI 的 API Key。建议使用Qwen-Max，因为它们对代码的分析和理解较为准确。API Key 支持持久化保存，方便下次自动加载。
   
   🧨白天推荐使用qwen，不卡速度快，但是缺点是没有deepdeek的理解思维好，生成的payload有点乱，晚上建议使用deepdeek或者非高峰期，不然会很卡，交流几次后会GG，优点是提示词理解度高，生成的payload比较好。
![image](https://github.com/user-attachments/assets/f92250a2-0d0c-402c-ad64-49a9cc18abe0)


---

## 工具使用

1. **抓包测试**  
   以宝塔 WAF 和 Pikachu 靶场为例，在靶场的 XSS 测试点抓包。  
   初始发送包含 XSS 代码的请求后，可看到目标返回 403 被 WAF 拦截的响应。
   ![image](https://github.com/user-attachments/assets/0c86878b-faf2-41ad-814b-471adeb90480)


2. **发送给 Chypass_pro**  
   将可能存在xss的数据包发送给Chypass_pro，然后在请求这边在疑似XSS的位置插入这个标签，然后点击保存模板(一定要保存)。
   <img width="987" alt="1741767848073" src="https://github.com/user-attachments/assets/bcb2529b-2b7e-467b-b327-5f1b4ff561bc" />
   ![image](https://github.com/user-attachments/assets/b4025c74-cffe-48da-a1db-01a684d15c82)




3. **启动 AI 分析**  
   下一步，点击AI分析即可，AI会自己通过判断每轮会生成不同的payload，我们也可也查看AI分析内容，方便我们后续手工和学习。
   ![image](https://github.com/user-attachments/assets/425603ed-e3bd-4239-a831-c29f373c32bd)


4. **查看结果**  
   我们可以对提示绕过waf的请求包右击，然后发送给重发器，然后我们就可以进行复测了(AI有时候生成的payload虽然可以绕过waf，但是不一定能正常触发，所以需要复测修改，例如下面)。
   ![image](https://github.com/user-attachments/assets/86ddd664-7bd4-4b84-8c61-7aa3bb217571)
   ![image](https://github.com/user-attachments/assets/bdde6c14-9bfb-414f-942d-41231666dda6)
5. **默认AI提示词调整**
   如果当前环境或者是当前payload生成效果不好，可以点击当前提示词，然后对默认提示词进行修改，然后选择保存提示词，保存后要点击清除全部记录，重新开始，这样的话后面的AI生成就会根据你新的提示词进行。 
   ![image](https://github.com/user-attachments/assets/2ee01640-d6be-4603-9138-f7bbc4b0f60a)
6.**报错解决**
   如果弹框如下，说明AI的回答的内容有问题或者是API卡死，需要清除全部内容后重新开始，其他报错弹框同理。
   ![image](https://github.com/user-attachments/assets/4111d514-d70a-4d39-8bfc-f3c21b201ee9)

---

## 工具目前没有解决的问题

🎃 大模型的API卡的问题 

🎃 大模型一会正常一会乱回答导致程序运行报错 

🎃 大模型提示词不完善，导致生成的payload质量低 

🎃 大模型的随机性，有时候几条就可以出bypass的payload，有时候要好久都出不了

---

## 其他问题
下面是各个大模型的API接口地址或者是帮助文档，大家可以查看申请API，大部分都需提前充值一点才可以使用。

通义大模型API开通地址：https://help.aliyun.com/zh/model-studio/developer-reference/get-api-key?spm=a2c4g.11186623.help-menu-2400256.d_3_0.74b04823hb1bFN

deepseek开通地址：https://platform.deepseek.com/api_keysx

siliconflow:https://docs.siliconflow.cn/cn/api-reference/chat-completions/chat-completions

siliconflow有15元的免费试用额度，大家可以试用

### 最后一点

payload的生成质量和大模型的数据样本、AI提示词直接挂钩，所以尽可能使用代码模型及样本较多的模型，此外不同场景，可以修改插件中的默认提示词，增加payload生成的质量和绕过率。 
- **注意事项**：  
  本工具仅供合法授权的安全测试使用，请勿用于非法用途。  
- **联系方式**：如有问题或建议，欢迎通过公众号联系我或提交 Issue，感谢师傅们支持！！。
- **公众号：白昼信安**
- 
  <img width="571" alt="Snipaste_2025-03-10_16-58-19" src="https://github.com/user-attachments/assets/d759b842-77e3-4e17-af35-711b90368133" />



---

_Chypass_pro_ —— 让数据包 + AI 驱动的 WAF 绕过测试更智能、更高效！
