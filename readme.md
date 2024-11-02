# 高级端口扫描器 (Advanced Port Scanner)

这是一个的现代化端口扫描器，提供美观的图形界面和强大的功能，可以帮助用户扫描指定域名或IP地址的端口状态。

## 功能特点

### 基础功能
- 现代化的图形界面，美观易用
- 支持域名和IP地址扫描
- 实时域名解析功能
- 多线程扫描，提高扫描效率
- 实时显示扫描进度和结果

### 端口选择
- 预定义端口组（Web服务、数据库等）
- 自定义端口范围
- 自定义端口列表
- 支持端口范围和单个端口混合输入

### 服务识别
- 基础服务识别
- 智能指纹识别（跳过可能产生乱码的服务）
- Web服务详细信息识别
- 常见服务版本识别

### 结果显示
- 清晰的表格式布局
- 自适应行高和列宽
- 交替行颜色显示
- 一键复制扫描结果
- 支持导出结果到CSV文件
- 支持生成HTML格式的扫描报告

### 配置管理
- 扫描配置管理对话框
- 创建、保存、删除和应用配置
- 配置持久化到JSON文件
- 自动加载最后使用的配置

## 系统要求
- 操作系统：Windows/Linux/MacOS

## 使用方法

### 基本操作
1. 启动程序：
   - 直接打开exe文件

2. 输入目标：
   - 在目标地址框中输入域名或IP
   - 点击"解析"按钮验证地址

3. 选择端口：
   - 从预定义组选择
   - 或设置自定义端口范围
   - 或输入自定义端口列表

4. 开始扫描：
   - 点击"开始扫描"按钮
   - 查看实时进度
   - 可随时停止扫描

### 结果管理
- 查看：在表格中实时显示扫描结果
- 复制：点击每行的"复制结果"按钮
- 导出：点击"导出结果"保存为CSV文件
- 生成报告：点击"生成报告"生成HTML格式的扫描报告

### 配置管理
- 打开配置管理对话框
- 创建、保存和删除配置
- 应用配置到扫描设置

## 界面说明

### 扫描设置区域
- 目标地址输入框：支持域名和IP地址
- 解析按钮：验证目标地址
- 端口选择：下拉菜单选择预定义组
- 端口范围设置：自定义起始和结束端口
- 自定义端口：输入特定端口列表

### 操作区域
- 开始/停止扫描按钮
- 导出结果按钮
- 生成报告按钮
- 扫描配置按钮

### 结果显示区域
- 端口列：显示端口号
- 状态列：显示端口状态
- 服务列：显示识别到的服务
- 操作列：包含复制按钮
- 进度条：显示扫描进度
- 状态栏：显示当前状态

## 配置文件

### port_config.json
- 存储预定义的端口组配置
- 包含常用端口组合
- 可自定义修改

### scan_config.json
- 存储扫描配置
- 支持多种扫描模式
- 自动加载最后使用的配置

## 注意事项

- 请合法使用本工具，不要对未经授权的目标进行扫描
- 扫描大范围端口可能需要较长时间
- 建议不要一次性扫描过多端口，以免影响网络性能
- 某些防火墙可能会阻止扫描行为
- 扫描结果仅供参考，可能存在误报或漏报

## 技术特点

- 使用 PyQt5 构建现代化界面
- 多线程设计，提高扫描效率
- 智能服务识别
- 异步处理，保持界面响应
- 优雅的错误处理机制
- 自适应界面布局

## 开发计划


## 贡献指南

欢迎提交问题和改进建议，如果您想贡献代码：
1. Fork 本项目
2. 创建您的特性分支
3. 提交您的改动
4. 推送到您的分支
5. 创建 Pull Request

## 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件

中文版请见 [LICENSE_CN](LICENSE_CN) 文件

## 联系方式

如有问题或建议，请提交 Issue 或发送邮件至 [fon1173@163.com]

## 致谢

感谢所有为本项目提供建议和帮助的贡献者。
