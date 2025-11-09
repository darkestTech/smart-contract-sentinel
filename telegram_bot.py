import os
import json
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes
from dotenv import load_dotenv
from analyzers.solidity_patterns import analyze_contract, save_scan_report
from analyzers.onchain_checks import check_honeypot_and_owner

# ---------------------------------------------------------------------------
# Load Environment
# ---------------------------------------------------------------------------
load_dotenv()
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")

# ---------------------------------------------------------------------------
# Core Commands
# ---------------------------------------------------------------------------

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "🛡️ *Smart Contract Sentinel Bot*\n"
        "Welcome! I can analyze verified token contracts on *Ethereum* and *BNB Chain*.\n\n"
        "📘 *Commands:*\n"
        "`/scan <address> <chain>` – Full static + on-chain analysis\n"
        "`/score <address> <chain>` – Quick risk score only\n"
        "`/last` – Show your most recent scan\n"
        "`/help` – Display this help message\n"
        "`/about` – Learn about this project\n\n"
        "💡 Example:\n"
        "`/scan 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 eth`\n"
        "`/scan 0x55d398326f99059fF775485246999027B3197955 bsc`"
    )
    await update.message.reply_text(msg, parse_mode="Markdown")

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await start(update, context)

async def about(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "🧠 *About Smart Contract Sentinel*\n"
        "Detects potential *rug pulls*, *honeypots*, and risky Solidity code.\n\n"
        "✅ Supports Ethereum & BNB Chain\n"
        "⚙️ Built with Python, Web3.py, and Telegram Bot API.\n\n"
        "Developed by *L1GHT* — powered by @ashon_chain."
    )
    await update.message.reply_text(msg, parse_mode="Markdown")

# ---------------------------------------------------------------------------
# /scan command
# ---------------------------------------------------------------------------

async def scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("⚠️ Usage: /scan <contract_address> <chain>")
        return

    address = context.args[0]
    chain = "ethereum"

    if len(context.args) > 1:
        chain = context.args[1].lower()

    # Support both ETH & BSC aliases
    if chain in ["eth"]:
        chain = "ethereum"
    elif chain in ["bnb", "bsc"]:
        chain = "bsc"

    if chain not in ["ethereum", "bsc"]:
        await update.message.reply_text("⚠️ Unsupported chain. Use 'eth' or 'bsc'.")
        return

    await update.message.reply_text(f"🔍 Scanning {address} on {chain.title()}...")

    try:
        results = analyze_contract(address, chain)
        onchain_results = check_honeypot_and_owner(address, chain)

        static_summary = next(
            (r["message"] for r in results if r["status"] == "📊 Summary"), "No summary."
        )

        reply = f"✅ *Static Analysis:*\n{static_summary}\n\n"
        reply += f"🔗 *On-Chain Checks ({chain.title()}):*\n"
        for k, v in onchain_results.items():
            reply += f"• {k}: {v}\n"

        save_scan_report(address, chain, results)
        context.user_data["last_report"] = {
            "address": address,
            "chain": chain,
            "summary": reply,
        }

        await update.message.reply_text(reply, parse_mode="Markdown")

    except Exception as e:
        await update.message.reply_text(f"❌ Scan failed: {e}")

# ---------------------------------------------------------------------------
# /score command
# ---------------------------------------------------------------------------

async def score(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("⚠️ Usage: /score <contract_address> <chain>")
        return

    address = context.args[0]
    chain = "ethereum"

    if len(context.args) > 1:
        chain = context.args[1].lower()

    if chain in ["eth"]:
        chain = "ethereum"
    elif chain in ["bnb", "bsc"]:
        chain = "bsc"

    await update.message.reply_text(f"📊 Calculating risk score for {address} on {chain.title()}...")

    try:
        results = analyze_contract(address, chain)
        static_summary = next(
            (r["message"] for r in results if r["status"] == "📊 Summary"), "No summary."
        )
        await update.message.reply_text(f"✅ {static_summary}")

    except Exception as e:
        await update.message.reply_text(f"❌ Failed to get score: {e}")

# ---------------------------------------------------------------------------
# /last command
# ---------------------------------------------------------------------------

async def last(update: Update, context: ContextTypes.DEFAULT_TYPE):
    last_report = context.user_data.get("last_report")
    if not last_report:
        await update.message.reply_text("📭 No previous scan found. Use /scan first.")
        return

    msg = (
        f"📝 *Last Scan Summary*\n"
        f"Contract: `{last_report['address']}`\n"
        f"Chain: {last_report['chain'].title()}\n\n"
        f"{last_report['summary']}"
    )
    await update.message.reply_text(msg, parse_mode="Markdown")

# ---------------------------------------------------------------------------
# Launch Bot
# ---------------------------------------------------------------------------

def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("about", about))
    app.add_handler(CommandHandler("scan", scan))
    app.add_handler(CommandHandler("score", score))
    app.add_handler(CommandHandler("last", last))

    print("🤖 Bot running... Press Ctrl + C to stop.")
    app.run_polling()

if __name__ == "__main__":
    main()
