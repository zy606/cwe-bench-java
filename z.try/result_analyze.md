
匹配的自然语言与代码（Matching NL-Code） 的平均相似度仅为 0.3176,完全不同的代码之间（Unrelated Code-Code） 的平均相似度却高达 0.4043,更令人震惊的是，80% 的随机代码对之间的相似度，都高于平均水平的“正确匹配”相似度。

这意味着，对于这个 Embedding 模型来说，“只要是代码，长得都像亲兄弟；至于这段代码和它的功能描述，仿佛是陌生人。”

以下是对这一现象背后 Root Cause 的深度阐述：

1. 语义鸿沟与抽象层级错位 (Semantic Gap & Abstraction Mismatch)
这是最根本的原因。自然语言描述和代码处于两个完全不同的抽象层级。

    -  自然语言（Intent/What）：描述的是意图和高层逻辑。关键词是抽象概念，如：“vulnerability”（漏洞）、“input sanitization”（输入清洗）、“bypass”（绕过）、“database”（数据库）。它描述的是“这段代码想做什么”以及“为什么它是不安全的”。

    - 代码（Implementation/How）：展示的是具体实现和底层细节。关键词是编程原语，如：if (x != null)、String query = ...、ResultSet、public void。它展示的是“这段代码具体怎么运行”。

    Embedding 模型的困境：通用的文本 Embedding 模型（如 BERT、RoBERTa 或未针对代码对齐微调的模型）主要基于分布假设（Contextual Distribution）。在它的训练语料中，“Sanitization”这个词周围常出现的是“Security”、“Check”、“Input”；而 executeQuery 周围常出现的是 Statement、try-catch。这两个语义空间在模型内部缺乏强有力的桥梁（Mapping），导致它们在向量空间中距离很远。


2. 代码的“结构性特征”压倒了“语义特征” (Structural Overpowering)为什么不相关的代码之间相似度这么高（0.4043）？

   句法强相似性：所有的 Java 漏洞代码，无论它是 SQL 注入还是 XSS，它们都共享着极高比例的“模版代码”：都包含 import java.util.*。都包含 public class ...。都包含 try { ... } catch (Exception e) { ... }。变量命名风格（驼峰命名）一致。

   模型视角的“走捷径”：对于一个通用模型来说，这些“Java 语法特征”是如此显著，以至于掩盖了代码内部细微的逻辑差异（比如是拼了 SQL 字符串还是拼了 HTML 字符串）。模型会认为：“这两个样本有 80% 的 token 结构是一样的（都是 Java 代码架构），所以它们肯定很相似。”


3. 缺乏“跨模态对齐”训练 (Lack of Cross-Modal Alignment)
这就像是让一个只学过中文和一个只学过英文的人对话，如果没有翻译（对齐），他们只能通过“语气”来判断对方。

   通用模型（如 jina-embeddings-v2-base-en）：主要是单模态训练（Text-Text）。它擅长判断“这句话和那句话是不是一个意思”。

   代码专用模型（如 CodeBERT、UniXcoder）：进行了专门的 Code-Text Pair 预训练。它们使用了类似“双塔结构”或“对比学习”的方法，强行拉近（Pull）匹配的代码-描述对，推远（Push）不匹配的对。

实验结果恰恰说明了使用的 Embedding 模型缺乏这种特定的“代码-文本对齐”能力。
这给任务二一个提示，Code Retrieval（代码检索）和 Code Understanding（代码理解）不能直接照搬 NLP 的方法
