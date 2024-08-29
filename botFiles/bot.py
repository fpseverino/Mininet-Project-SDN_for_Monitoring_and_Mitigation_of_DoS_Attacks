import logging
from telegram import KeyboardButton, ReplyKeyboardMarkup, Update
from telegram.ext import Application, CallbackQueryHandler, CommandHandler, ContextTypes, ApplicationBuilder, MessageHandler, filters
from threading import Thread
import time
import os
import json

js = {}
loc_chat_id_list = []

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)


def load_stats():

    while(True):
    
        global js 
        
        if os.path.exists('filestats.txt'):
                with open('filestats.txt', "r") as file:
                    data = file.read()
                    file.close()

                js = json.loads(data)
        time.sleep(5)
        
        
def write_ids(update):
    global loc_chat_id_list
    
    if update.message.chat_id not in loc_chat_id_list:
        loc_chat_id_list.append(update.message.chat_id)

    with open("chat_id_list.txt", "w") as file:
    
       for id in loc_chat_id_list:
           file.write(str(id))
           file.write("\n")

            

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):

    write_ids(update)
      
    keyboard = [
        [
            KeyboardButton("🗺 Topologia"),
            KeyboardButton("📊 Statistiche"),
        ]
    ]

    reply_markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True, one_time_keyboard=True)

    await update.message.reply_text("Scegli un'opzione.", reply_markup=reply_markup)


# Funzione per gestire la risposta in base all'opzione selezionata
async def handle_response(update: Update, context: ContextTypes.DEFAULT_TYPE):
    
    user_choice = update.message.text
    global js
    write_ids(update)

    # Controllo della scelta dell'utente e risposta corrispondente
    if user_choice == "🗺 Topologia":
        if os.path.exists('../topology.png'):
            await update.message.reply_photo(photo=open('../topology.png', 'rb'))
        else:
            await update.message.reply_text("Nessuna topologia in esecuzione o il file non esiste.")

    elif user_choice == "📊 Statistiche":

        if os.path.exists('filestats.txt'):
            with open('filestats.txt', "r") as file:
                data = file.read()
                file.close()

            js = json.loads(data)

            if len(js) == 0:
                await update.message.reply_text("Non sono disponibili statistiche in questo momento.")
                return

            keyb = [
                [
                    KeyboardButton("🔀 Switch " + str(key)) for key in js.keys()
                ],
                [KeyboardButton("🔙 Indietro")]
            ]

            reply_markup = ReplyKeyboardMarkup(keyb, resize_keyboard=True, one_time_keyboard=True)

            await update.message.reply_text("Scegli uno switch di cui mostrare le statistiche.", reply_markup=reply_markup)

        else:
            await update.message.reply_text("Nessuna topologia in esecuzione o il file non esiste.")

    elif user_choice.startswith("🔀 Switch"):

        value = user_choice.split(" ")[2]

        msg = "<b>Statistiche per " + user_choice + "</b>\n "
        tab = "    "

        prev = ""

        for flow in js[value].keys():
            newline = "\n"
            port = "<b>🚪 Porta: " + flow.split("-")[0] + "</b>"
            src = "📤 MAC Sorgente: " + flow.split("-")[1]
            dst = "📥 MAC Destinazione: " + flow.split("-")[2]
            cont = "🧮 Stato Conteggio: " + js[value][flow].split("-")[0]
            alarm_status = "🚨 Stato allarme: " + js[value][flow].split("-")[1]
            adv = "⚠️ Penalità stimata: " + str(pow(7, int(js[value][flow].split("-")[1]) + 1)) + " sec."

            if port == prev:
                msg = newline + msg + newline + tab + newline + tab + src + tab + newline + tab + dst + newline + tab + cont + newline + tab + alarm_status + newline + tab + adv + newline
            else:
                msg = newline + msg + newline + port + newline + tab + newline + tab + src + tab + newline + tab + dst + newline + tab + cont + newline + tab + alarm_status + newline + tab + adv + newline

            prev = port

        await update.message.reply_text(msg, parse_mode="HTML")

    elif user_choice == "🔙 Indietro":
        keyboard = [
            [
                KeyboardButton("🗺 Topologia"),
                KeyboardButton("📊 Statistiche"),
            ]
        ]

        reply_markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True, one_time_keyboard=True)

        await update.message.reply_text("Scegli un'opzione.", reply_markup=reply_markup)

    else:
        await update.message.reply_text("Scegliere una delle opzioni del menù. Se non compare, scrivere /start.")


if __name__ == '__main__':
    application = ApplicationBuilder().token('7470407133:AAHKFLviL_l9BDVqX14uZfeUs9gePitSuNI').build()

    start_handler = CommandHandler('start', start)

    application.add_handler(start_handler)

    # Aggiunta dell'handler per gestire le risposte dell'utente
    response_handler = MessageHandler(filters.TEXT & ~filters.COMMAND, handle_response)
    application.add_handler(response_handler)
    
    

    if os.path.exists('filestats.txt'):
        with open('filestats.txt', "r") as file:
            data = file.read()
            file.close()

        js = json.loads(data)
        
    t = Thread(target = load_stats)
    t.start()

    application.run_polling()
    t.join()
