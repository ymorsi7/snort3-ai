#!/bin/bash
# Project Structure Cleanup Script
# This script organizes the SNORT AI project into a clean structure

echo "🧹 CLEANING UP PROJECT STRUCTURE"
echo "================================"

# Create organized directory structure
mkdir -p src/{core,evaluation,analysis,utils}
mkdir -p docs/{results,reports}
mkdir -p config/{rules,models}
mkdir -p scripts

echo "📁 Created organized directory structure"

# Move core files to appropriate directories
echo "📦 Organizing files..."

# Core SNORT AI implementation
if [ -f "src/detection/gpt_assist.cc" ]; then
    echo "✅ Core SNORT AI implementation already in src/"
fi

# Move evaluation scripts
mv paper_ready_evaluation.py src/evaluation/
mv academic_snort_evaluation.py src/evaluation/
mv truly_academic_evaluation.py src/evaluation/

# Move analysis scripts  
mv comprehensive_model_comparison.py src/analysis/
mv final_comprehensive_analysis.py src/analysis/
mv cost_analysis.py src/analysis/

# Move utility scripts
mv compare_openai_models.py src/utils/
mv best_model_test.py src/utils/
mv test_openai_integration.py src/utils/

# Move configuration files
mv *.rules config/rules/ 2>/dev/null || true
mv *.conf config/ 2>/dev/null || true

# Move results and reports
mv *results docs/results/ 2>/dev/null || true
mv COMPREHENSIVE_QUANTITATIVE_ANALYSIS.txt docs/reports/ 2>/dev/null || true
mv *.md docs/ 2>/dev/null || true

# Move scripts
mv create_test_pcap.py scripts/
mv generate_sample_data.py scripts/
mv security_check.sh scripts/

echo "✅ Files organized into clean structure"

# Remove redundant/outdated files
echo "🗑️  Removing redundant files..."

# Remove old evaluation scripts (keep only the latest versions)
rm -f cicids2017_evaluate.py
rm -f cicids2017_academic_evaluate.py  
rm -f comprehensive_cicids2017_evaluate.py
rm -f efficient_academic_evaluation.py
rm -f academic_payload_evaluation.py
rm -f academic_pcap_snort_evaluation.py
rm -f fixed_snort_evaluate.py
rm -f final_academic_evaluation.py
rm -f evaluate.py
rm -f enhanced_model_comparison.py
rm -f comprehensive_quantitative_analysis.py

echo "✅ Removed redundant evaluation scripts"

# Remove test/development files
rm -f create_test_pcap.py
rm -f test.pcap
rm -f test_real.pcap

echo "✅ Removed test files"

# Remove old documentation
rm -f FINAL_*.md
rm -f HONEST_*.md
rm -f REAL_*.md
rm -f IMPLEMENTATION_*.md

echo "✅ Removed outdated documentation"

echo ""
echo "🎯 PROJECT STRUCTURE CLEANUP COMPLETE"
echo "======================================"
echo "📁 Organized structure:"
echo "   • src/core/ - Core SNORT AI implementation"
echo "   • src/evaluation/ - Academic evaluation scripts"
echo "   • src/analysis/ - Model comparison and analysis"
echo "   • src/utils/ - Utility scripts"
echo "   • config/ - Configuration files and rules"
echo "   • docs/ - Documentation and results"
echo "   • scripts/ - Helper scripts"
echo ""
echo "✅ Repository is now clean and organized!"
