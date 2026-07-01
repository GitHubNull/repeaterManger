#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Code Quality Statistics Tool for Java Projects
统计Java项目代码质量指标：总行数、逻辑行数、注释行数、空行数、import行数、
package行数、函数数量、类数量、平均函数行数等

支持导出：Markdown报告、HTML图表报告、CSV明细、JSON数据
默认输出目录：项目根目录/tmp/
"""

import os
import re
import sys
import json
import csv
from pathlib import Path
from collections import defaultdict
from datetime import datetime


class JavaFileStats:
    """单个Java文件的统计信息"""
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.file_name = os.path.basename(file_path)
        self.total_lines = 0
        self.blank_lines = 0
        self.comment_lines = 0
        self.import_lines = 0
        self.package_lines = 0
        self.logic_lines = 0
        self.class_count = 0
        self.method_count = 0
        self.javadoc_lines = 0
        self.inline_comment_lines = 0
        self.block_comment_lines = 0
        # 新增：类详情和方法详情
        self.classes = []  # [{name, start_line, end_line, line_count, method_count}]
        self.methods = []  # [{name, class_name, start_line, end_line, line_count}]
        # 代码质量评级
        self.quality_score = 0
        self.risk_level = 'low'  # low, medium, high, critical
        
    def to_dict(self):
        return {
            'file_path': self.file_path,
            'file_name': self.file_name,
            'total_lines': self.total_lines,
            'blank_lines': self.blank_lines,
            'comment_lines': self.comment_lines,
            'javadoc_lines': self.javadoc_lines,
            'inline_comment_lines': self.inline_comment_lines,
            'block_comment_lines': self.block_comment_lines,
            'import_lines': self.import_lines,
            'package_lines': self.package_lines,
            'logic_lines': self.logic_lines,
            'class_count': self.class_count,
            'method_count': self.method_count,
            'classes': self.classes,
            'methods': self.methods,
            'quality_score': self.quality_score,
            'risk_level': self.risk_level,
        }


class CodeQualityStats:
    """代码质量统计器"""
    
    # 方法签名正则表达式
    METHOD_PATTERN = re.compile(
        r'^\s*(?:(?:public|private|protected|static|final|abstract|synchronized|native|strictfp)\s+)*'
        r'(?:<[\w\s,<>?]+>\s+)?'
        r'(?:[\w\[\]<>]+\s+)?'
        r'([\w$]+)\s*\([^)]*\)\s*(?:throws\s+[\w\s,]+)?\s*\{',
        re.MULTILINE
    )
    
    # 类定义正则
    CLASS_PATTERN = re.compile(
        r'^\s*(?:(?:public|private|protected|static|final|abstract)\s+)*'
        r'(?:class|interface|enum|record)\s+(\w+)',
        re.MULTILINE
    )
    
    def __init__(self, project_root: str = '.'):
        self.project_root = Path(project_root).resolve()
        self.file_stats = []
        self.summary = {}
        # 确保tmp目录存在
        self.output_dir = self.project_root / 'tmp' / 'code_quality_stats_reports'
        self.output_dir.mkdir(parents=True, exist_ok=True)
        # 时间戳
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
    def find_java_files(self) -> list:
        """查找所有Java文件（排除target、.git等目录）"""
        java_files = []
        exclude_dirs = {'.git', 'target', 'build', '.idea', '.vscode', 'tmp', 'out'}
        
        for root, dirs, files in os.walk(self.project_root):
            # 排除指定目录
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            
            for file in files:
                if file.endswith('.java'):
                    java_files.append(os.path.join(root, file))
                    
        return sorted(java_files)
    
    def _find_method_boundaries(self, content: str, lines: list) -> list:
        """查找所有方法的起止行和名称"""
        methods = []
        for match in self.METHOD_PATTERN.finditer(content):
            method_name = match.group(1)
            start_line = content[:match.start()].count('\n') + 1
            
            # 找到方法体结束位置（通过花括号匹配）
            body_start = match.end() - 1  # 指向 '{'
            brace_count = 1
            pos = body_start + 1
            
            while pos < len(content) and brace_count > 0:
                if content[pos] == '{':
                    brace_count += 1
                elif content[pos] == '}':
                    brace_count -= 1
                pos += 1
                
            end_line = content[:pos].count('\n') + 1
            line_count = end_line - start_line + 1
            
            methods.append({
                'name': method_name,
                'start_line': start_line,
                'end_line': end_line,
                'line_count': line_count,
                'class_name': None,  # 后续填充
            })
            
        return methods
    
    def _find_class_boundaries(self, content: str, lines: list) -> list:
        """查找所有类的起止行和名称"""
        classes = []
        for match in self.CLASS_PATTERN.finditer(content):
            class_name = match.group(1)
            start_line = content[:match.start()].count('\n') + 1
            
            # 找到类体结束位置
            body_start = content.find('{', match.end())
            if body_start == -1:
                continue
                
            brace_count = 1
            pos = body_start + 1
            
            while pos < len(content) and brace_count > 0:
                if content[pos] == '{':
                    brace_count += 1
                elif content[pos] == '}':
                    brace_count -= 1
                pos += 1
                
            end_line = content[:pos].count('\n') + 1
            line_count = end_line - start_line + 1
            
            classes.append({
                'name': class_name,
                'start_line': start_line,
                'end_line': end_line,
                'line_count': line_count,
                'method_count': 0,  # 后续填充
            })
            
        return classes
    
    def _assign_methods_to_classes(self, methods: list, classes: list):
        """将方法归属到对应的类"""
        for method in methods:
            for cls in classes:
                if cls['start_line'] <= method['start_line'] <= cls['end_line']:
                    method['class_name'] = cls['name']
                    cls['method_count'] += 1
                    break
                    
    def _calculate_file_quality(self, stats: JavaFileStats):
        """计算文件质量评分和风险等级"""
        score = 100
        
        # 文件长度扣分
        if stats.total_lines > 1000:
            score -= 20
        elif stats.total_lines > 500:
            score -= 10
            
        # 注释比例扣分
        comment_ratio = stats.comment_lines / stats.total_lines if stats.total_lines > 0 else 0
        if comment_ratio < 0.05:
            score -= 15
        elif comment_ratio < 0.1:
            score -= 5
            
        # 方法数量扣分
        if stats.method_count > 50:
            score -= 20
        elif stats.method_count > 30:
            score -= 10
            
        # 空行比例扣分
        blank_ratio = stats.blank_lines / stats.total_lines if stats.total_lines > 0 else 0
        if blank_ratio < 0.1:
            score -= 5
            
        stats.quality_score = max(0, score)
        
        # 风险等级
        if stats.total_lines > 1000 or stats.method_count > 50:
            stats.risk_level = 'critical'
        elif stats.total_lines > 500 or stats.method_count > 30:
            stats.risk_level = 'high'
        elif stats.total_lines > 300 or stats.method_count > 20:
            stats.risk_level = 'medium'
        else:
            stats.risk_level = 'low'
    
    def analyze_file(self, file_path: str) -> JavaFileStats:
        """分析单个Java文件"""
        stats = JavaFileStats(file_path)
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            print(f"Warning: 无法读取文件 {file_path}: {e}")
            return stats
            
        lines = content.split('\n')
        stats.total_lines = len(lines)
        
        in_block_comment = False
        
        for line in lines:
            stripped = line.strip()
            
            # 空行
            if not stripped:
                stats.blank_lines += 1
                continue
                
            # package行
            if stripped.startswith('package '):
                stats.package_lines += 1
                continue
                
            # import行
            if stripped.startswith('import '):
                stats.import_lines += 1
                continue
                
            # 块注释处理
            if in_block_comment:
                stats.comment_lines += 1
                stats.block_comment_lines += 1
                if '*/' in stripped:
                    in_block_comment = False
                continue
                
            # 块注释开始
            if stripped.startswith('/*'):
                stats.comment_lines += 1
                stats.block_comment_lines += 1
                if stripped.startswith('/**'):
                    stats.javadoc_lines += 1
                if not stripped.endswith('*/'):
                    in_block_comment = True
                continue
                
            # 行注释
            if stripped.startswith('//'):
                stats.comment_lines += 1
                stats.inline_comment_lines += 1
                continue
                
            # 行尾注释（也算注释行）
            if '//' in stripped:
                stats.comment_lines += 1
                stats.inline_comment_lines += 1
                code_part = stripped.split('//')[0].strip()
                if code_part:
                    stats.logic_lines += 1
                continue
                
            # 逻辑行
            stats.logic_lines += 1
            
        # 统计类和函数
        stats.classes = self._find_class_boundaries(content, lines)
        stats.methods = self._find_method_boundaries(content, lines)
        self._assign_methods_to_classes(stats.methods, stats.classes)
        
        stats.class_count = len(stats.classes)
        stats.method_count = len(stats.methods)
        
        # 计算质量评分
        self._calculate_file_quality(stats)
        
        return stats
    
    def analyze_project(self):
        """分析整个项目"""
        java_files = self.find_java_files()
        
        if not java_files:
            print("未找到Java文件！")
            return
            
        print(f"找到 {len(java_files)} 个Java文件，开始分析...")
        
        for file_path in java_files:
            stats = self.analyze_file(file_path)
            self.file_stats.append(stats)
            
        self._calculate_summary()
        
    def _calculate_summary(self):
        """计算汇总数据"""
        if not self.file_stats:
            return
            
        total_files = len(self.file_stats)
        total_lines = sum(s.total_lines for s in self.file_stats)
        blank_lines = sum(s.blank_lines for s in self.file_stats)
        comment_lines = sum(s.comment_lines for s in self.file_stats)
        javadoc_lines = sum(s.javadoc_lines for s in self.file_stats)
        inline_comment_lines = sum(s.inline_comment_lines for s in self.file_stats)
        block_comment_lines = sum(s.block_comment_lines for s in self.file_stats)
        import_lines = sum(s.import_lines for s in self.file_stats)
        package_lines = sum(s.package_lines for s in self.file_stats)
        logic_lines = sum(s.logic_lines for s in self.file_stats)
        total_classes = sum(s.class_count for s in self.file_stats)
        total_methods = sum(s.method_count for s in self.file_stats)
        
        # 收集所有方法和类
        all_methods = []
        all_classes = []
        for s in self.file_stats:
            for m in s.methods:
                m['file_name'] = s.file_name
                all_methods.append(m)
            for c in s.classes:
                c['file_name'] = s.file_name
                all_classes.append(c)
                
        # 计算平均值
        avg_lines_per_file = total_lines / total_files if total_files > 0 else 0
        avg_logic_lines_per_file = logic_lines / total_files if total_files > 0 else 0
        avg_methods_per_class = total_methods / total_classes if total_classes > 0 else 0
        avg_lines_per_method = logic_lines / total_methods if total_methods > 0 else 0
        avg_class_length = sum(c['line_count'] for c in all_classes) / len(all_classes) if all_classes else 0
        avg_method_length = sum(m['line_count'] for m in all_methods) / len(all_methods) if all_methods else 0
        
        # 代码质量指标
        comment_ratio = (comment_lines / total_lines * 100) if total_lines > 0 else 0
        blank_ratio = (blank_lines / total_lines * 100) if total_lines > 0 else 0
        logic_ratio = (logic_lines / total_lines * 100) if total_lines > 0 else 0
        import_ratio = (import_lines / total_lines * 100) if total_lines > 0 else 0
        
        # 风险文件统计
        risk_counts = defaultdict(int)
        for s in self.file_stats:
            risk_counts[s.risk_level] += 1
            
        self.summary = {
            'project_root': str(self.project_root),
            'analysis_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_files': total_files,
            'total_lines': total_lines,
            'blank_lines': blank_lines,
            'comment_lines': comment_lines,
            'javadoc_lines': javadoc_lines,
            'inline_comment_lines': inline_comment_lines,
            'block_comment_lines': block_comment_lines,
            'import_lines': import_lines,
            'package_lines': package_lines,
            'logic_lines': logic_lines,
            'total_classes': total_classes,
            'total_methods': total_methods,
            'avg_lines_per_file': round(avg_lines_per_file, 2),
            'avg_logic_lines_per_file': round(avg_logic_lines_per_file, 2),
            'avg_methods_per_class': round(avg_methods_per_class, 2),
            'avg_lines_per_method': round(avg_lines_per_method, 2),
            'avg_class_length': round(avg_class_length, 2),
            'avg_method_length': round(avg_method_length, 2),
            'comment_ratio': round(comment_ratio, 2),
            'blank_ratio': round(blank_ratio, 2),
            'logic_ratio': round(logic_ratio, 2),
            'import_ratio': round(import_ratio, 2),
            'risk_counts': dict(risk_counts),
            'all_methods': all_methods,
            'all_classes': all_classes,
        }
        
    def print_report(self):
        """打印统计报告"""
        if not self.summary:
            print("没有可显示的数据，请先运行 analyze_project()")
            return
            
        print("\n" + "=" * 80)
        print("                    Java 代码质量统计报告")
        print("=" * 80)
        print(f"项目路径: {self.summary['project_root']}")
        print(f"分析时间: {self.summary['analysis_time']}")
        print("-" * 80)
        
        print("\n【基础统计】")
        print(f"  Java文件总数:       {self.summary['total_files']:>8} 个")
        print(f"  总物理行数:         {self.summary['total_lines']:>8} 行")
        print(f"  纯逻辑行数:         {self.summary['logic_lines']:>8} 行  ({self.summary['logic_ratio']}%)")
        print(f"  空行数:             {self.summary['blank_lines']:>8} 行  ({self.summary['blank_ratio']}%)")
        print(f"  注释行数:           {self.summary['comment_lines']:>8} 行  ({self.summary['comment_ratio']}%)")
        print(f"    - Javadoc注释:    {self.summary['javadoc_lines']:>8} 行")
        print(f"    - 行内注释:       {self.summary['inline_comment_lines']:>8} 行")
        print(f"    - 块注释:         {self.summary['block_comment_lines']:>8} 行")
        print(f"  Import语句:         {self.summary['import_lines']:>8} 行  ({self.summary['import_ratio']}%)")
        print(f"  Package声明:        {self.summary['package_lines']:>8} 行")
        
        print("\n【代码结构】")
        print(f"  类/接口/枚举总数:   {self.summary['total_classes']:>8} 个")
        print(f"  方法总数:           {self.summary['total_methods']:>8} 个")
        print(f"  平均每文件行数:     {self.summary['avg_lines_per_file']:>8.2f} 行")
        print(f"  平均每文件逻辑行:   {self.summary['avg_logic_lines_per_file']:>8.2f} 行")
        print(f"  平均每类方法数:     {self.summary['avg_methods_per_class']:>8.2f} 个")
        print(f"  平均方法逻辑行数:   {self.summary['avg_lines_per_method']:>8.2f} 行")
        print(f"  平均类长度:         {self.summary['avg_class_length']:>8.2f} 行")
        print(f"  平均方法长度:       {self.summary['avg_method_length']:>8.2f} 行")
        
        print("\n【质量指标】")
        comment_density = self.summary['comment_ratio']
        if comment_density >= 20:
            comment_grade = "优秀"
        elif comment_density >= 10:
            comment_grade = "良好"
        elif comment_density >= 5:
            comment_grade = "一般"
        else:
            comment_grade = "偏低"
        print(f"  注释覆盖率:         {comment_density:>8.2f}%  [{comment_grade}]")
        
        blank_density = self.summary['blank_ratio']
        if 15 <= blank_density <= 25:
            blank_grade = "合理"
        elif blank_density < 15:
            blank_grade = "偏少"
        else:
            blank_grade = "偏多"
        print(f"  空行比例:           {blank_density:>8.2f}%  [{blank_grade}]")
        
        method_lines = self.summary['avg_lines_per_method']
        if method_lines <= 20:
            method_grade = "优秀"
        elif method_lines <= 50:
            method_grade = "良好"
        elif method_lines <= 100:
            method_grade = "一般"
        else:
            method_grade = "偏长"
        print(f"  平均方法长度:       {method_lines:>8.2f} 行  [{method_grade}]")
        
        # 风险文件统计
        print("\n【风险文件分布】")
        risk_labels = {'critical': '严重', 'high': '高危', 'medium': '中危', 'low': '低危'}
        for level in ['critical', 'high', 'medium', 'low']:
            count = self.summary['risk_counts'].get(level, 0)
            print(f"  {risk_labels[level]:>4}风险: {count:>3} 个文件")
            
        print("\n" + "=" * 80)
        
    def print_file_rankings(self):
        """打印文件行数排名（最高和最低）"""
        print("\n【文件行数排名 - 最高 Top 20】")
        sorted_files = sorted(self.file_stats, key=lambda x: x.total_lines, reverse=True)
        for i, stats in enumerate(sorted_files[:20], 1):
            risk_label = {'critical': '!!', 'high': '! ', 'medium': '  ', 'low': '  '}
            print(f"  {i:2d}. {risk_label[stats.risk_level]}{stats.file_name:<50} "
                  f"{stats.total_lines:>6} 行  "
                  f"(逻辑:{stats.logic_lines:>5} 注释:{stats.comment_lines:>4} "
                  f"类:{stats.class_count:>2} 方法:{stats.method_count:>3} "
                  f"质量:{stats.quality_score:>3})")
                  
        print("\n【文件行数排名 - 最低 Top 20】")
        for i, stats in enumerate(sorted_files[-20:], 1):
            print(f"  {i:2d}. {stats.file_name:<50} "
                  f"{stats.total_lines:>6} 行  "
                  f"(逻辑:{stats.logic_lines:>5} 注释:{stats.comment_lines:>4} "
                  f"类:{stats.class_count:>2} 方法:{stats.method_count:>3})")
                  
    def print_class_rankings(self):
        """打印类长度排名"""
        all_classes = self.summary.get('all_classes', [])
        if not all_classes:
            return
            
        print("\n【类长度排名 - 最高 Top 20】")
        sorted_classes = sorted(all_classes, key=lambda x: x['line_count'], reverse=True)
        for i, cls in enumerate(sorted_classes[:20], 1):
            print(f"  {i:2d}. {cls['name']:<40} ({cls['file_name']:<30}) "
                  f"{cls['line_count']:>5} 行  方法:{cls['method_count']:>3}")
                  
        print("\n【类长度排名 - 最低 Top 20】")
        for i, cls in enumerate(sorted_classes[-20:], 1):
            print(f"  {i:2d}. {cls['name']:<40} ({cls['file_name']:<30}) "
                  f"{cls['line_count']:>5} 行  方法:{cls['method_count']:>3}")
                  
    def print_method_rankings(self):
        """打印方法长度排名"""
        all_methods = self.summary.get('all_methods', [])
        if not all_methods:
            return
            
        print("\n【方法长度排名 - 最高 Top 30】")
        sorted_methods = sorted(all_methods, key=lambda x: x['line_count'], reverse=True)
        for i, method in enumerate(sorted_methods[:30], 1):
            class_info = f".{method['class_name']}" if method['class_name'] else ""
            print(f"  {i:2d}. {method['name']}{class_info:<35} ({method['file_name']:<30}) "
                  f"{method['line_count']:>4} 行  "
                  f"[{method['start_line']}-{method['end_line']}]")
                  
        print("\n【方法长度排名 - 最低 Top 20】")
        for i, method in enumerate(sorted_methods[-20:], 1):
            class_info = f".{method['class_name']}" if method['class_name'] else ""
            print(f"  {i:2d}. {method['name']}{class_info:<35} ({method['file_name']:<30}) "
                  f"{method['line_count']:>4} 行")
                  
    def print_risk_files(self):
        """打印风险文件详情"""
        print("\n【风险文件详情 - 需要优先重构】")
        risk_files = [s for s in self.file_stats if s.risk_level in ['critical', 'high']]
        risk_files.sort(key=lambda x: x.total_lines, reverse=True)
        
        for stats in risk_files:
            risk_label = {'critical': '【严重】', 'high': '【高危】'}
            print(f"\n  {risk_label[stats.risk_level]}{stats.file_name}")
            print(f"      总行数: {stats.total_lines} | 逻辑行: {stats.logic_lines} | "
                  f"方法数: {stats.method_count} | 类数: {stats.class_count} | "
                  f"质量分: {stats.quality_score}")
            print(f"      路径: {stats.file_path}")
            
            # 列出该文件中最长的方法
            if stats.methods:
                long_methods = sorted(stats.methods, key=lambda x: x['line_count'], reverse=True)[:5]
                print(f"      最长方法:")
                for m in long_methods:
                    print(f"        - {m['name']}: {m['line_count']} 行 [{m['start_line']}-{m['end_line']}]")
                    
    def print_quality_suggestions(self):
        """打印代码质量改进建议"""
        print("\n【代码质量改进建议】")
        
        suggestions = []
        
        # 检查超长文件
        long_files = [s for s in self.file_stats if s.total_lines > 500]
        if long_files:
            suggestions.append(f"1. 超长文件拆分: 有 {len(long_files)} 个文件超过500行，建议拆分为更小的类")
            
        # 检查方法过长
        long_methods = [m for m in self.summary.get('all_methods', []) if m['line_count'] > 100]
        if long_methods:
            suggestions.append(f"2. 方法过长优化: 有 {len(long_methods)} 个方法超过100行，建议提取子方法")
            
        # 检查类过大
        large_classes = [c for c in self.summary.get('all_classes', []) if c['line_count'] > 500]
        if large_classes:
            suggestions.append(f"3. 大类拆分: 有 {len(large_classes)} 个类超过500行，建议按职责拆分")
            
        # 检查注释不足
        low_comment = [s for s in self.file_stats if s.comment_lines / s.total_lines < 0.05 and s.total_lines > 100]
        if low_comment:
            suggestions.append(f"4. 注释补充: 有 {len(low_comment)} 个文件注释率低于5%，建议添加Javadoc")
            
        # 检查空行不足
        low_blank = [s for s in self.file_stats if s.blank_lines / s.total_lines < 0.1 and s.total_lines > 100]
        if low_blank:
            suggestions.append(f"5. 可读性优化: 有 {len(low_blank)} 个文件空行比例低于10%，建议增加空行分隔逻辑块")
            
        # 检查方法过多
        many_methods = [s for s in self.file_stats if s.method_count > 30]
        if many_methods:
            suggestions.append(f"6. 方法数量控制: 有 {len(many_methods)} 个文件方法数超过30个，建议拆分职责")
            
        if not suggestions:
            suggestions.append("代码质量整体良好，暂无重大改进建议")
            
        for suggestion in suggestions:
            print(f"  {suggestion}")
            
    def print_top_methods_per_file(self, n: int = 10):
        """打印方法数最多的文件"""
        print(f"\n【方法数最多文件 Top {n}】")
        sorted_files = sorted(self.file_stats, key=lambda x: x.method_count, reverse=True)[:n]
        for i, stats in enumerate(sorted_files, 1):
            print(f"  {i:2d}. {stats.file_name:<50} {stats.method_count:>3} 个方法  "
                  f"(类:{stats.class_count:>2} 总行:{stats.total_lines:>6})")
    
    # ==================== Markdown报告生成 ====================
    def export_markdown(self, output_path: str = None):
        """导出Markdown报告"""
        if output_path is None:
            output_path = self.output_dir / f'code_quality_report_{self.timestamp}.md'
        
        md_content = self._generate_markdown()
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(md_content)
            
        print(f"\nMarkdown报告已导出: {output_path}")
        return str(output_path)
    
    def _generate_markdown(self) -> str:
        """生成Markdown内容"""
        s = self.summary
        
        md = f"""# Java 代码质量统计报告

> **项目路径**: `{s['project_root']}`  
> **分析时间**: {s['analysis_time']}  
> **生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

## 一、基础统计

| 指标 | 数值 | 占比 |
|------|------|------|
| Java文件总数 | **{s['total_files']}** 个 | - |
| 总物理行数 | **{s['total_lines']:,}** 行 | 100% |
| 纯逻辑行数 | **{s['logic_lines']:,}** 行 | {s['logic_ratio']}% |
| 空行数 | {s['blank_lines']:,} 行 | {s['blank_ratio']}% |
| 注释行数 | {s['comment_lines']:,} 行 | {s['comment_ratio']}% |
| Import语句 | {s['import_lines']:,} 行 | {s['import_ratio']}% |
| Package声明 | {s['package_lines']:,} 行 | - |

### 注释行细分

| 类型 | 行数 |
|------|------|
| Javadoc注释 | {s['javadoc_lines']:,} 行 |
| 行内注释 | {s['inline_comment_lines']:,} 行 |
| 块注释 | {s['block_comment_lines']:,} 行 |

---

## 二、代码结构

| 指标 | 数值 |
|------|------|
| 类/接口/枚举总数 | {s['total_classes']} 个 |
| 方法总数 | {s['total_methods']} 个 |
| 平均每文件行数 | {s['avg_lines_per_file']:.2f} 行 |
| 平均每文件逻辑行 | {s['avg_logic_lines_per_file']:.2f} 行 |
| 平均每类方法数 | {s['avg_methods_per_class']:.2f} 个 |
| 平均方法逻辑行数 | {s['avg_lines_per_method']:.2f} 行 |
| 平均类长度 | {s['avg_class_length']:.2f} 行 |
| 平均方法长度 | {s['avg_method_length']:.2f} 行 |

---

## 三、质量指标

| 指标 | 数值 | 评级 |
|------|------|------|
| 注释覆盖率 | {s['comment_ratio']:.2f}% | {'优秀' if s['comment_ratio'] >= 20 else '良好' if s['comment_ratio'] >= 10 else '一般' if s['comment_ratio'] >= 5 else '偏低'} |
| 空行比例 | {s['blank_ratio']:.2f}% | {'合理' if 15 <= s['blank_ratio'] <= 25 else '偏少' if s['blank_ratio'] < 15 else '偏多'} |
| 平均方法长度 | {s['avg_lines_per_method']:.2f} 行 | {'优秀' if s['avg_lines_per_method'] <= 20 else '良好' if s['avg_lines_per_method'] <= 50 else '一般' if s['avg_lines_per_method'] <= 100 else '偏长'} |

### 风险文件分布

| 风险等级 | 数量 |
|----------|------|
| 严重风险 | {s['risk_counts'].get('critical', 0)} 个文件 |
| 高危风险 | {s['risk_counts'].get('high', 0)} 个文件 |
| 中危风险 | {s['risk_counts'].get('medium', 0)} 个文件 |
| 低危风险 | {s['risk_counts'].get('low', 0)} 个文件 |

---

## 四、文件行数排名

### 最高 Top 20

| 排名 | 风险 | 文件名 | 总行数 | 逻辑行 | 注释 | 类 | 方法 | 质量分 |
|------|------|--------|--------|--------|------|-----|------|--------|
"""
        sorted_files = sorted(self.file_stats, key=lambda x: x.total_lines, reverse=True)
        for i, stats in enumerate(sorted_files[:20], 1):
            risk_icon = {'critical': '!!', 'high': '!', 'medium': '~', 'low': ' '}
            md += f"| {i} | {risk_icon[stats.risk_level]} | {stats.file_name} | {stats.total_lines} | {stats.logic_lines} | {stats.comment_lines} | {stats.class_count} | {stats.method_count} | {stats.quality_score} |\n"
        
        md += "\n### 最低 Top 20\n\n| 排名 | 文件名 | 总行数 | 逻辑行 | 注释 | 类 | 方法 |\n|------|--------|--------|--------|------|-----|------|\n"
        for i, stats in enumerate(sorted_files[-20:], 1):
            md += f"| {i} | {stats.file_name} | {stats.total_lines} | {stats.logic_lines} | {stats.comment_lines} | {stats.class_count} | {stats.method_count} |\n"
        
        md += "\n---\n\n## 五、类长度排名\n\n### 最高 Top 20\n\n| 排名 | 类名 | 所在文件 | 长度 | 方法数 |\n|------|------|----------|------|--------|\n"
        all_classes = s.get('all_classes', [])
        sorted_classes = sorted(all_classes, key=lambda x: x['line_count'], reverse=True)
        for i, cls in enumerate(sorted_classes[:20], 1):
            md += f"| {i} | `{cls['name']}` | {cls['file_name']} | {cls['line_count']} | {cls['method_count']} |\n"
        
        md += "\n### 最低 Top 20\n\n| 排名 | 类名 | 所在文件 | 长度 | 方法数 |\n|------|------|----------|------|--------|\n"
        for i, cls in enumerate(sorted_classes[-20:], 1):
            md += f"| {i} | `{cls['name']}` | {cls['file_name']} | {cls['line_count']} | {cls['method_count']} |\n"
        
        md += "\n---\n\n## 六、方法长度排名\n\n### 最高 Top 30\n\n| 排名 | 方法名 | 所在文件 | 长度 | 行号范围 |\n|------|--------|----------|------|----------|\n"
        all_methods = s.get('all_methods', [])
        sorted_methods = sorted(all_methods, key=lambda x: x['line_count'], reverse=True)
        for i, method in enumerate(sorted_methods[:30], 1):
            class_info = f".{method['class_name']}" if method['class_name'] else ""
            md += f"| {i} | `{method['name']}{class_info}` | {method['file_name']} | {method['line_count']} | [{method['start_line']}-{method['end_line']}] |\n"
        
        md += "\n---\n\n## 七、风险文件详情\n\n"
        risk_files = [st for st in self.file_stats if st.risk_level in ['critical', 'high']]
        risk_files.sort(key=lambda x: x.total_lines, reverse=True)
        for stats in risk_files:
            risk_label = {'critical': '【严重】', 'high': '【高危】'}
            md += f"### {risk_label[stats.risk_level]}{stats.file_name}\n\n"
            md += f"- **总行数**: {stats.total_lines} | **逻辑行**: {stats.logic_lines} | **方法数**: {stats.method_count}\n"
            md += f"- **类数**: {stats.class_count} | **质量分**: {stats.quality_score}\n"
            md += f"- **路径**: `{stats.file_path}`\n\n"
            if stats.methods:
                long_methods = sorted(stats.methods, key=lambda x: x['line_count'], reverse=True)[:5]
                md += "**最长方法**:\n\n| 方法名 | 长度 | 行号范围 |\n|--------|------|----------|\n"
                for m in long_methods:
                    md += f"| `{m['name']}` | {m['line_count']} 行 | [{m['start_line']}-{m['end_line']}] |\n"
            md += "\n"
        
        md += "---\n\n## 八、代码质量改进建议\n\n"
        suggestions = []
        long_files = [st for st in self.file_stats if st.total_lines > 500]
        if long_files:
            suggestions.append(f"1. **超长文件拆分**: 有 {len(long_files)} 个文件超过500行，建议拆分为更小的类")
        long_methods = [m for m in s.get('all_methods', []) if m['line_count'] > 100]
        if long_methods:
            suggestions.append(f"2. **方法过长优化**: 有 {len(long_methods)} 个方法超过100行，建议提取子方法")
        large_classes = [c for c in s.get('all_classes', []) if c['line_count'] > 500]
        if large_classes:
            suggestions.append(f"3. **大类拆分**: 有 {len(large_classes)} 个类超过500行，建议按职责拆分")
        low_comment = [st for st in self.file_stats if st.comment_lines / st.total_lines < 0.05 and st.total_lines > 100]
        if low_comment:
            suggestions.append(f"4. **注释补充**: 有 {len(low_comment)} 个文件注释率低于5%，建议添加Javadoc")
        low_blank = [st for st in self.file_stats if st.blank_lines / st.total_lines < 0.1 and st.total_lines > 100]
        if low_blank:
            suggestions.append(f"5. **可读性优化**: 有 {len(low_blank)} 个文件空行比例低于10%，建议增加空行分隔逻辑块")
        many_methods = [st for st in self.file_stats if st.method_count > 30]
        if many_methods:
            suggestions.append(f"6. **方法数量控制**: 有 {len(many_methods)} 个文件方法数超过30个，建议拆分职责")
        if not suggestions:
            suggestions.append("代码质量整体良好，暂无重大改进建议")
        for suggestion in suggestions:
            md += f"- {suggestion}\n"
        
        md += "\n---\n\n*报告由 code_quality_stats.py 自动生成*\n"
        return md
    
    # ==================== HTML图表报告生成 ====================
    def export_html(self, output_path: str = None):
        """导出HTML图表报告"""
        if output_path is None:
            output_path = self.output_dir / f'code_quality_report_{self.timestamp}.html'
        
        html_content = self._generate_html()
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        print(f"\nHTML报告已导出: {output_path}")
        return str(output_path)
    
    def _generate_html(self) -> str:
        """生成HTML内容（含图表）"""
        s = self.summary
        
        # 准备图表数据
        sorted_files = sorted(self.file_stats, key=lambda x: x.total_lines, reverse=True)
        top_files = sorted_files[:15]
        file_names = [f.file_name[:20] for f in top_files]
        file_lines = [f.total_lines for f in top_files]
        file_logic = [f.logic_lines for f in top_files]
        file_comments = [f.comment_lines for f in top_files]
        
        # 风险分布数据
        risk_data = s.get('risk_counts', {})
        risk_labels = ['严重', '高危', '中危', '低危']
        risk_values = [risk_data.get('critical', 0), risk_data.get('high', 0), 
                       risk_data.get('medium', 0), risk_data.get('low', 0)]
        risk_colors = ['#e74c3c', '#e67e22', '#f39c12', '#27ae60']
        
        # 代码构成数据
        composition_labels = ['逻辑行', '注释行', '空行', 'Import', 'Package']
        composition_values = [s['logic_lines'], s['comment_lines'], s['blank_lines'], 
                              s['import_lines'], s['package_lines']]
        composition_colors = ['#3498db', '#9b59b6', '#95a5a6', '#1abc9c', '#34495e']
        
        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Java 代码质量统计报告 - {s['analysis_time']}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; 
                background: #f5f7fa; color: #333; line-height: 1.6; }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; 
                   padding: 40px; border-radius: 12px; margin-bottom: 30px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .header p {{ opacity: 0.9; font-size: 1.1em; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .stat-card {{ background: white; padding: 25px; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.08); 
                      transition: transform 0.2s; }}
        .stat-card:hover {{ transform: translateY(-3px); box-shadow: 0 4px 20px rgba(0,0,0,0.12); }}
        .stat-card .label {{ color: #666; font-size: 0.9em; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; }}
        .stat-card .value {{ font-size: 2em; font-weight: bold; color: #2c3e50; }}
        .stat-card .sub {{ color: #999; font-size: 0.85em; margin-top: 5px; }}
        .chart-section {{ background: white; padding: 30px; border-radius: 12px; margin-bottom: 30px; 
                          box-shadow: 0 2px 10px rgba(0,0,0,0.08); }}
        .chart-section h2 {{ color: #2c3e50; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #eee; }}
        .chart-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 30px; }}
        .chart-container {{ position: relative; height: 350px; }}
        .table-section {{ background: white; padding: 30px; border-radius: 12px; margin-bottom: 30px; 
                          box-shadow: 0 2px 10px rgba(0,0,0,0.08); overflow-x: auto; }}
        .table-section h2 {{ color: #2c3e50; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #eee; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #eee; }}
        th {{ background: #f8f9fa; font-weight: 600; color: #555; }}
        tr:hover {{ background: #f8f9fa; }}
        .risk-critical {{ color: #e74c3c; font-weight: bold; }}
        .risk-high {{ color: #e67e22; font-weight: bold; }}
        .risk-medium {{ color: #f39c12; }}
        .risk-low {{ color: #27ae60; }}
        .badge {{ display: inline-block; padding: 4px 10px; border-radius: 12px; font-size: 0.8em; font-weight: 600; }}
        .badge-critical {{ background: #fee; color: #c0392b; }}
        .badge-high {{ background: #fff3e0; color: #e65100; }}
        .badge-medium {{ background: #fff8e1; color: #f57f17; }}
        .badge-low {{ background: #e8f5e9; color: #2e7d32; }}
        .suggestions {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; 
                        padding: 30px; border-radius: 12px; margin-bottom: 30px; }}
        .suggestions h2 {{ margin-bottom: 20px; }}
        .suggestions ul {{ list-style: none; }}
        .suggestions li {{ padding: 10px 0; border-bottom: 1px solid rgba(255,255,255,0.2); }}
        .suggestions li:last-child {{ border-bottom: none; }}
        .footer {{ text-align: center; padding: 20px; color: #999; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Java 代码质量统计报告</h1>
            <p>项目: {s['project_root']} | 分析时间: {s['analysis_time']}</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="label">Java文件总数</div>
                <div class="value">{s['total_files']}</div>
                <div class="sub">个文件</div>
            </div>
            <div class="stat-card">
                <div class="label">总物理行数</div>
                <div class="value">{s['total_lines']:,}</div>
                <div class="sub">行代码</div>
            </div>
            <div class="stat-card">
                <div class="label">纯逻辑行数</div>
                <div class="value">{s['logic_lines']:,}</div>
                <div class="sub">{s['logic_ratio']}% 占比</div>
            </div>
            <div class="stat-card">
                <div class="label">注释覆盖率</div>
                <div class="value">{s['comment_ratio']:.1f}%</div>
                <div class="sub">{s['comment_lines']:,} 行注释</div>
            </div>
            <div class="stat-card">
                <div class="label">方法总数</div>
                <div class="value">{s['total_methods']}</div>
                <div class="sub">平均 {s['avg_lines_per_method']:.1f} 行/方法</div>
            </div>
            <div class="stat-card">
                <div class="label">类总数</div>
                <div class="value">{s['total_classes']}</div>
                <div class="sub">平均 {s['avg_methods_per_class']:.1f} 方法/类</div>
            </div>
        </div>
        
        <div class="chart-grid">
            <div class="chart-section">
                <h2>代码构成分析</h2>
                <div class="chart-container">
                    <canvas id="compositionChart"></canvas>
                </div>
            </div>
            <div class="chart-section">
                <h2>风险文件分布</h2>
                <div class="chart-container">
                    <canvas id="riskChart"></canvas>
                </div>
            </div>
        </div>
        
        <div class="chart-section">
            <h2>Top 15 文件行数分布</h2>
            <div class="chart-container" style="height: 450px;">
                <canvas id="fileChart"></canvas>
            </div>
        </div>
        
        <div class="table-section">
            <h2>文件行数排名 - 最高 Top 20</h2>
            <table>
                <thead>
                    <tr><th>排名</th><th>风险</th><th>文件名</th><th>总行数</th><th>逻辑行</th><th>注释</th><th>类</th><th>方法</th><th>质量分</th></tr>
                </thead>
                <tbody>
"""
        for i, stats in enumerate(sorted_files[:20], 1):
            risk_class = f"risk-{stats.risk_level}"
            badge_class = f"badge-{stats.risk_level}"
            risk_text = {'critical': '严重', 'high': '高危', 'medium': '中危', 'low': '低危'}
            html += f"""                    <tr>
                        <td>{i}</td>
                        <td><span class="badge {badge_class}">{risk_text[stats.risk_level]}</span></td>
                        <td>{stats.file_name}</td>
                        <td class="{risk_class}">{stats.total_lines}</td>
                        <td>{stats.logic_lines}</td>
                        <td>{stats.comment_lines}</td>
                        <td>{stats.class_count}</td>
                        <td>{stats.method_count}</td>
                        <td>{stats.quality_score}</td>
                    </tr>
"""
        
        html += """                </tbody>
            </table>
        </div>
        
        <div class="table-section">
            <h2>方法长度排名 - 最高 Top 20</h2>
            <table>
                <thead>
                    <tr><th>排名</th><th>方法名</th><th>所在文件</th><th>长度</th><th>行号范围</th></tr>
                </thead>
                <tbody>
"""
        all_methods = s.get('all_methods', [])
        sorted_methods = sorted(all_methods, key=lambda x: x['line_count'], reverse=True)
        for i, method in enumerate(sorted_methods[:20], 1):
            class_info = f".{method['class_name']}" if method['class_name'] else ""
            html += f"""                    <tr>
                        <td>{i}</td>
                        <td><code>{method['name']}{class_info}</code></td>
                        <td>{method['file_name']}</td>
                        <td class="{'risk-critical' if method['line_count'] > 100 else 'risk-high' if method['line_count'] > 50 else ''}">{method['line_count']} 行</td>
                        <td>[{method['start_line']}-{method['end_line']}]</td>
                    </tr>
"""
        
        html += """                </tbody>
            </table>
        </div>
        
        <div class="suggestions">
            <h2>代码质量改进建议</h2>
            <ul>
"""
        suggestions = []
        long_files = [st for st in self.file_stats if st.total_lines > 500]
        if long_files:
            suggestions.append(f"超长文件拆分: 有 {len(long_files)} 个文件超过500行，建议拆分为更小的类")
        long_methods = [m for m in s.get('all_methods', []) if m['line_count'] > 100]
        if long_methods:
            suggestions.append(f"方法过长优化: 有 {len(long_methods)} 个方法超过100行，建议提取子方法")
        large_classes = [c for c in s.get('all_classes', []) if c['line_count'] > 500]
        if large_classes:
            suggestions.append(f"大类拆分: 有 {len(large_classes)} 个类超过500行，建议按职责拆分")
        low_comment = [st for st in self.file_stats if st.comment_lines / st.total_lines < 0.05 and st.total_lines > 100]
        if low_comment:
            suggestions.append(f"注释补充: 有 {len(low_comment)} 个文件注释率低于5%，建议添加Javadoc")
        low_blank = [st for st in self.file_stats if st.blank_lines / st.total_lines < 0.1 and st.total_lines > 100]
        if low_blank:
            suggestions.append(f"可读性优化: 有 {len(low_blank)} 个文件空行比例低于10%，建议增加空行分隔逻辑块")
        many_methods = [st for st in self.file_stats if st.method_count > 30]
        if many_methods:
            suggestions.append(f"方法数量控制: 有 {len(many_methods)} 个文件方法数超过30个，建议拆分职责")
        if not suggestions:
            suggestions.append("代码质量整体良好，暂无重大改进建议")
        for suggestion in suggestions:
            html += f"                <li>{suggestion}</li>\n"
        
        html += f"""            </ul>
        </div>
        
        <div class="footer">
            <p>报告由 code_quality_stats.py 自动生成 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>
    
    <script>
        // 代码构成饼图
        new Chart(document.getElementById('compositionChart'), {{
            type: 'doughnut',
            data: {{
                labels: {json.dumps(composition_labels)},
                datasets: [{{
                    data: {json.dumps(composition_values)},
                    backgroundColor: {json.dumps(composition_colors)},
                    borderWidth: 2,
                    borderColor: '#fff'
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{ position: 'bottom' }}
                }}
            }}
        }});
        
        // 风险分布饼图
        new Chart(document.getElementById('riskChart'), {{
            type: 'pie',
            data: {{
                labels: {json.dumps(risk_labels)},
                datasets: [{{
                    data: {json.dumps(risk_values)},
                    backgroundColor: {json.dumps(risk_colors)},
                    borderWidth: 2,
                    borderColor: '#fff'
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{ position: 'bottom' }}
                }}
            }}
        }});
        
        // 文件行数堆叠柱状图
        new Chart(document.getElementById('fileChart'), {{
            type: 'bar',
            data: {{
                labels: {json.dumps(file_names)},
                datasets: [
                    {{
                        label: '逻辑行',
                        data: {json.dumps(file_logic)},
                        backgroundColor: '#3498db'
                    }},
                    {{
                        label: '注释行',
                        data: {json.dumps(file_comments)},
                        backgroundColor: '#9b59b6'
                    }}
                ]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                scales: {{
                    x: {{ stacked: true }},
                    y: {{ stacked: true, beginAtZero: true }}
                }},
                plugins: {{
                    legend: {{ position: 'top' }}
                }}
            }}
        }});
    </script>
</body>
</html>
"""
        return html
    
    # ==================== CSV和JSON导出 ====================
    def export_csv(self, output_path: str = None):
        """导出CSV明细"""
        if output_path is None:
            output_path = self.output_dir / f'code_quality_detail_{self.timestamp}.csv'
            
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            if self.file_stats:
                writer = csv.DictWriter(f, fieldnames=self.file_stats[0].to_dict().keys())
                writer.writeheader()
                for stats in self.file_stats:
                    writer.writerow(stats.to_dict())
                    
        print(f"CSV明细已导出: {output_path}")
        return str(output_path)
        
    def export_json(self, output_path: str = None):
        """导出JSON报告"""
        if output_path is None:
            output_path = self.output_dir / f'code_quality_data_{self.timestamp}.json'
            
        report = {
            'summary': self.summary,
            'files': [s.to_dict() for s in self.file_stats]
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
            
        print(f"JSON数据已导出: {output_path}")
        return str(output_path)


def main():
    """主函数"""
    # 确定项目根目录
    script_dir = Path(__file__).parent.resolve()
    project_root = script_dir.parent
    
    print(f"开始分析项目: {project_root}")
    
    # 创建统计器并分析
    stats = CodeQualityStats(project_root)
    stats.analyze_project()
    
    # 打印报告
    stats.print_report()
    stats.print_file_rankings()
    stats.print_class_rankings()
    stats.print_method_rankings()
    stats.print_risk_files()
    stats.print_quality_suggestions()
    stats.print_top_methods_per_file(10)
    
    # 导出所有报告
    print("\n" + "=" * 80)
    print("                    导出报告文件")
    print("=" * 80)
    stats.export_markdown()
    stats.export_html()
    stats.export_csv()
    stats.export_json()
    
    print(f"\n所有报告已保存到: {stats.output_dir}")
    print("分析完成！")


if __name__ == '__main__':
    main()
