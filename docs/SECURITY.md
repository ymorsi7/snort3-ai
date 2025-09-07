# 🚨 SECURITY WARNING

## ⚠️ CRITICAL: API Keys and Sensitive Data Protection

**NEVER commit API keys, passwords, or sensitive data to version control!**

### 🔐 What to Protect:
- API keys (OpenAI, Claude, Google, etc.)
- Database credentials
- SNORT configuration files with sensitive rules
- Personal authentication tokens
- Private keys and certificates

### 📁 Files Already Protected by .gitignore:
- `*.key`, `*.pem`, `*.p12`, `*.pfx`
- `*.conf`, `*.rules` (SNORT configs)
- `*.pcap`, `*.cap` (large network captures)
- `*.parquet`, `*.csv` (large datasets)
- `*.zip`, `*.tar.gz` (archives)
- Environment files (`.env`, `.env.local`)
- Virtual environments (`venv/`, `academic_env/`)

### 🛡️ Security Best Practices:

1. **Use Environment Variables:**
   ```bash
   export OPENAI_API_KEY="your_key_here"
   export CLAUDE_API_KEY="your_key_here"
   ```

2. **Create .env files (never commit them):**
   ```bash
   # .env (add to .gitignore)
   OPENAI_API_KEY=your_key_here
   CLAUDE_API_KEY=your_key_here
   ```

3. **Use Configuration Templates:**
   ```python
   # config_template.py
   OPENAI_API_KEY = "your_openai_api_key_here"
   CLAUDE_API_KEY = "your_claude_api_key_here"
   ```

4. **Check Before Committing:**
   ```bash
   # Search for potential API keys
   grep -r "sk-" . --exclude-dir=.git
   grep -r "AIzaSy" . --exclude-dir=.git
   ```

### 🔍 Large Files Already Excluded:
- `cicids2017/` (258MB) - Academic dataset
- `pcap-data/` (4.8GB) - Network captures
- `real_pcaps/` (6.1MB) - PCAP files
- `*.zip` files (1GB+ total)

### ⚡ Quick Security Check:
```bash
# Check for exposed API keys
grep -r "sk-ant-api03\|sk-proj-\|AIzaSy" . --exclude-dir=.git

# Check file sizes
du -sh * | sort -hr | head -10

# Verify .gitignore is working
git status --ignored
```

### 🚨 If You Accidentally Commit Sensitive Data:
1. **Immediately revoke/regenerate** the exposed API keys
2. **Remove from git history:**
   ```bash
   git filter-branch --force --index-filter \
   'git rm --cached --ignore-unmatch filename' \
   --prune-empty --tag-name-filter cat -- --all
   ```
3. **Force push** to update remote repository
4. **Notify team members** to update their local copies

### 📞 Security Contact:
If you discover a security vulnerability or accidentally commit sensitive data, please:
1. Immediately revoke any exposed credentials
2. Create a security issue in the repository
3. Contact the maintainers privately

---
**Remember: Security is everyone's responsibility! 🔒**
