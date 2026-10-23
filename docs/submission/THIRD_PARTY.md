# 第三方模型与来源

随包的本地语义模型为 `sentence-transformers/all-MiniLM-L6-v2` 的既有 FastEmbed ONNX 工件，文件哈希由 `data/models/manifest.json` 逐项绑定；仅清单中的路径改为相对路径，模型文件未修改。其上游[模型卡](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2)标注 Apache-2.0，许可文本随附于 [Apache-2.0.txt](licenses/Apache-2.0.txt)。模型属于其原作者，不能视为项目自研模型。

清单中少量 `._` 文件属于原模型工件的既有哈希集合，为保持当前向量和模型摘要绑定而保留。其他未使用模型缓存没有进入提交包。

公开情报原文仍保留原始 URL、采集 origin、时间、版本及 SHA-256，用于本项目研究演示和结论追溯。公开可访问不代表项目拥有这些来源内容的版权。软件依赖及其许可由安装的各自发行包提供；本项目未重新授权第三方软件或模型。
