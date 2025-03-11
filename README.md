# Chypass_pro

> 一个基于 AI 自动绕过 WAF、完成 XSS 漏洞测试的 Burp Suite 扩展

---
**打包后的jar部分环境会导致AI一直卡在开始会话这里，正在重新打包修复ing ing！！！！！！

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
- **Java 11 版本**
请根据你的环境选择对应版本进行下载和使用。

### 安装步骤

1. **下载插件**  
   下载对应的 jar 包（Java 8 或 Java 11 版本）。
![image](https://github.com/user-attachments/assets/8fe5be9a-a3ec-478a-94db-8eb742cb295b)

2. **导入插件**  
   在 Burp Suite 中选择 **Extender** → **Extensions**，点击 **Add**，选择 **Java** 类型，然后加载你下载的 jar 文件。![image](https://github.com/user-attachments/assets/0635a147-0123-4ac6-8a53-7a33c60a3317)


3. **配置 API Key**  
   导入插件后，请先配置 AI 的 API Key。建议使用 DeepSeek 或 Qwen-Max，因为它们对代码的分析和理解较为准确。API Key 支持持久化保存，方便下次自动加载。
![image](https://github.com/user-attachments/assets/b197ce9d-3d41-40eb-a7f6-9eb98a089d94)
![image](https://github.com/user-attachments/assets/4bdaa40e-59eb-42bf-90fa-53e4e84579e1)

---

## 工具使用

1. **抓包测试**  
   以宝塔 WAF 和 Pikachu 靶场为例，在靶场的 XSS 测试点抓包。  
   初始发送包含 XSS 代码的请求后，可看到目标返回 403 被 WAF 拦截的响应。![image](https://github.com/user-attachments/assets/0c86878b-faf2-41ad-814b-471adeb90480)


2. **发送给 Chypass_pro**  
   右击选中该数据包，选择 “Send to Chypass” 将请求数据发入插件中。
   ![image](https://github.com/user-attachments/assets/a99a0f36-1c3a-4df0-880f-fe135773c8a8)


4. **启动 AI 分析**  
   点击 “开启 AI 分析”，插件会自动对请求包和返回包进行分析，并生成可绕过 WAF 的 payload，再次发送改造后的请求。
   <img width="445" alt="1741594774967" src="https://github.com/user-attachments/assets/7faeb632-30f7-455e-a6ec-d27fdc3570c6" />
   ![image](https://github.com/user-attachments/assets/04971004-0676-4c1e-9315-e1fdbb4e00c6)

6. **查看结果**  
   稍等片刻后，历史记录侧边栏会显示多个绕过宝塔 WAF 的 payload 供参考。
   ![image](https://github.com/user-attachments/assets/610de6ee-82c9-4e5f-8354-881b40b89575)
   使用AI生成的payload成功绕过宝塔的xss拦截。
   ![image](https://github.com/user-attachments/assets/4fd8bcf3-21a5-4557-a536-afc4822868aa)
---

## 后续更新

这个工具的逻辑和我之前的一些想法不谋而合，单纯依靠 FUZZ 绕过 WAF 确实不够高效。未来我将持续更新该工具，加入更多智能化功能和调试优化，欢迎各位师傅提供建议和改进思路！

---

## 其他说明

- **原项目地址**：请参考上面的链接。  
- **注意事项**：  
  本工具仅供合法授权的安全测试使用，请勿用于非法用途。  
- **联系方式**：如有问题或建议，欢迎留言或提交 Issue。
- **公众号：白昼信安**
- 
  <img width="571" alt="Snipaste_2025-03-10_16-58-19" src="https://github.com/user-attachments/assets/d759b842-77e3-4e17-af35-711b90368133" />



---

_Chypass_pro_ —— 让数据包 + AI 驱动的 WAF 绕过测试更智能、更高效！
