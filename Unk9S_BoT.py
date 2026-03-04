#!/usr/bin/env python
# coding=utf-8
# https://t.me/unk9vvn
# AVI
import telegram, logging, wget, requests, os, glob, time, random, subprocess, getpass, string
from telegram import *
from telegram.ext import *


logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)
DOWN_UP, DOWNLOADING, UPLOADING, RESTART = range(4)


def start(bot, update):
    bot.send_chat_action(chat_id=update.message.chat_id, action=telegram.ChatAction.TYPING)
    reply_keyboard = [['Downloader', 'Uploader'],
                      ['Admin']]
    update.message.reply_text(
        text="""⤴️ گزینه Downloader به منظور ساخت لینک از فایل Forward شده شما سرویس میدهد.

⤵️ گزینه Uploader به منظور آپلود انواع فایل ها بر روی سرور تلگرام میباشد.

🔄 برای استفاده دوباره از ربات گزینه restart را کلیک کنید.

/restart""",
        reply_markup=ReplyKeyboardMarkup(reply_keyboard, one_time_keyboard=True))

    return DOWN_UP


def downloader(bot, update):
    bot.send_chat_action(chat_id=update.message.chat_id, action=telegram.ChatAction.TYPING)
    user = update.message.from_user
    logger.info("File of %s: %s", user.first_name, update.message.text)
    update.message.reply_text('🌀 فایل مورد نظر خود را Forward نمایید.'
                              '\n/restart',
                              reply_markup=ReplyKeyboardRemove())

    return DOWNLOADING


@run_async
def downloading(bot, update):
    global filename
    bot.send_chat_action(chat_id=update.message.chat_id, action=telegram.ChatAction.TYPING)
    message = update.message
    user = update.message.from_user
    logger.info("User %s did send a File.", user.first_name)
    rnd = ''.join(random.choice(string.ascii_lowercase) for i in range(10))
    cwd = os.getcwd()
    dir_down = cwd + '\\tmp_down'
    name_ins = cwd + '\MEGAcmdSetup.exe'
    user_win = getpass.getuser()
    dir_mega = 'C:\Users\{0}\AppData\Local\MEGAcmd"'.format(user_win)
    installer = 'https://mega.nz/MEGAcmdSetup.exe'
    megadir = os.path.exists(dir_mega)
    if megadir == (True):
        wget.download(installer, cwd)
        subprocess.Popen(
            'cmd.exe /c "SET PATH=%PATH%;C:\Windows\System32\WindowsPowerShell\/v1.0"',
            shell=True)
        subprocess.Popen(
            'powershell.exe -Command "$pathvargs = {%s /S /v/qn };Invoke-Command -ScriptBlock $pathvargs"' %(name_ins),
            shell=True)
        time.sleep(10)
        subprocess.Popen(
            'cmd.exe /c "SET PATH=%PATH%;C:\Users\{0}\AppData\Local\MEGAcmd"'.format(user_win),
            shell=True)
        subprocess.Popen(
            'start cmd.exe /c "MEGAcmdServer"',
            shell=True)
        subprocess.Popen(
            'mega-login Email Password',
            shell=True)
    else:
        subprocess.Popen(
            'start cmd.exe /c "MEGAcmdServer"',
            shell=True)

    if message.document:
        rnd_link = rnd
        query = update.callback_query
        document_id = message.document.file_id
        filename = message.document.file_name
        down_file = dir_down + '\\' + filename
        rnd_nam_link = rnd_link + '.txt'
        dir_rnd_nam_link = dir_down + '\\' + rnd_nam_link
        newFile = bot.get_file(document_id)
        bot.send_chat_action(chat_id=update.message.chat_id, action=telegram.ChatAction.TYPING)
        update.message.reply_text('↙️ فایل مورد نظر در حال آپلود بر روی سرور mega میبباشد, لطفا صبور باشید...')
        newFile.download(down_file)
        time.sleep(2)
        bot.send_chat_action(chat_id=update.message.chat_id, action=telegram.ChatAction.UPLOAD_DOCUMENT)
        subprocess.call('mega-put -c "{0}"'.format(down_file), shell=True)
        subprocess.call('mega-export -a "%s" > %s' %(filename, dir_rnd_nam_link), shell=True)
        lines = open(dir_rnd_nam_link, "r+").readlines()
        lines = [x.strip() for x in lines]
        link = "".join(lines)
        link = link.replace("Exported /{0}: ".format(filename), "")
        executor = link
        commandline = open(dir_rnd_nam_link, 'w')
        commandline.write(executor)
        commandline.close()
        with open(dir_rnd_nam_link) as myfile:
            link_open = myfile.read()
        bot.send_message(chat_id=update.message.chat_id, text='%s\n🌀 طول عمر لینک 6 ساعت میباشد.\n\n/restart' %(link_open),
                         reply_markup=ReplyKeyboardRemove())
        os.remove(down_file)
        os.remove(dir_rnd_nam_link)
        subprocess.Popen(
            'start cmd.exe /c "timeout 21600 & mega-rm -r \'%s\'"' %(filename),
            shell=True)

    elif message.photo:
        rnd_photo = rnd
        rnd_link = rnd
        rnd_nam_photo = rnd_photo + '.jpg'
        rnd_nam_link = rnd_link + '.txt'
        dir_rnd_nam_link = dir_down + '\\' + rnd_nam_link
        photo_id = message.photo[-1].file_id
        down_photo = dir_down + '\\' + rnd_nam_photo
        newFile = bot.get_file(photo_id)
        bot.send_chat_action(chat_id=update.message.chat_id, action=telegram.ChatAction.TYPING)
        update.message.reply_text('↙️ فایل مورد نظر در حال آپلود بر روی سرور mega میبباشد, لطفا صبور باشید...')
        newFile.download(down_photo)
        time.sleep(2)
        bot.send_chat_action(chat_id=update.message.chat_id, action=telegram.ChatAction.UPLOAD_PHOTO)
        subprocess.call('mega-put -c "{0}"'.format(down_photo), shell=True)
        subprocess.call('mega-export -a "%s" > %s' %(rnd_nam_photo, dir_rnd_nam_link), shell=True)
        lines = open(dir_rnd_nam_link, "r+").readlines()
        lines = [x.strip() for x in lines]
        link = "".join(lines)
        link = link.replace("Exported /{0}: ".format(filename), "")
        executor = link
        commandline = open(dir_rnd_nam_link, 'w')
        commandline.write(executor)
        commandline.close()
        with open(dir_rnd_nam_link) as myfile:
            link_open = myfile.read()
        bot.send_message(chat_id=update.message.chat_id, text='%s\n🌀 طول عمر لینک 6 ساعت میباشد.\n\n/restart' %(link_open),
                         reply_markup=ReplyKeyboardRemove())
        os.remove(down_photo)
        os.remove(dir_rnd_nam_link)
        subprocess.Popen(
            'start cmd.exe /c "timeout 21600 & mega-rm -r \'%s\'"' % (rnd_nam_photo),
            shell=True)

    elif message.video:
        rnd_video = rnd
        rnd_link = rnd
        rnd_nam_video = rnd_video + '.mp4'
        rnd_nam_link = rnd_link + '.txt'
        dir_rnd_nam_link = dir_down + '\\' + rnd_nam_link
        video_id = message.video.file_id
        down_video = dir_down + '\\' + rnd_nam_video
        newFile = bot.get_file(video_id)
        bot.send_chat_action(chat_id=update.message.chat_id, action=telegram.ChatAction.TYPING)
        update.message.reply_text('↙️ فایل مورد نظر در حال آپلود بر روی سرور mega میبباشد, لطفا صبور باشید...')
        newFile.download(down_video)
        time.sleep(2)
        bot.send_chat_action(chat_id=update.message.chat_id, action=telegram.ChatAction.UPLOAD_VIDEO)
        subprocess.call('mega-put -c "{0}"'.format(down_video), shell=True)
        subprocess.call('mega-export -a "%s" > %s' % (rnd_nam_video, dir_rnd_nam_link), shell=True)
        lines = open(dir_rnd_nam_link, "r+").readlines()
        lines = [x.strip() for x in lines]
        link = "".join(lines)
        link = link.replace("Exported /{0}: ".format(filename), "")
        executor = link
        commandline = open(dir_rnd_nam_link, 'w')
        commandline.write(executor)
        commandline.close()
        with open(dir_rnd_nam_link) as myfile:
            link_open = myfile.read()
        bot.send_message(chat_id=update.message.chat_id, text='%s\n🌀 طول عمر لینک 6 ساعت میباشد.\n\n/restart' %(link_open),
                         reply_markup=ReplyKeyboardRemove())
        os.remove(down_video)
        os.remove(dir_rnd_nam_link)
        subprocess.Popen(
            'start cmd.exe /c "timeout 21600 & mega-rm -r \'%s\'"' % (rnd_nam_video),
            shell=True)

    elif message.audio:
        bot.send_chat_action(chat_id=update.message.chat_id, action=telegram.ChatAction.TYPING)
        rnd_audio = rnd
        rnd_link = rnd
        rnd_nam_audio = rnd_audio + '.mp3'
        rnd_nam_link = rnd_link + '.txt'
        dir_rnd_nam_link = dir_down + '\\' + rnd_nam_link
        audio_id = message.audio.file_id
        down_audio = dir_down + '\\' + rnd_nam_audio
        newFile = bot.get_file(audio_id)
        bot.send_chat_action(chat_id=update.message.chat_id, action=telegram.ChatAction.TYPING)
        update.message.reply_text('↙️ فایل مورد نظر در حال آپلود بر روی سرور mega میبباشد, لطفا صبور باشید...')
        newFile.download(down_audio)
        time.sleep(2)
        bot.send_chat_action(chat_id=update.message.chat_id, action=telegram.ChatAction.UPLOAD_AUDIO)
        subprocess.call('mega-put -c "{0}"'.format(down_audio), shell=True)
        subprocess.call('mega-export -a "%s" > %s' % (rnd_nam_audio, dir_rnd_nam_link), shell=True)
        lines = open(dir_rnd_nam_link, "r+").readlines()
        lines = [x.strip() for x in lines]
        link = "".join(lines)
        link = link.replace("Exported /{0}: ".format(filename), "")
        executor = link
        commandline = open(dir_rnd_nam_link, 'w')
        commandline.write(executor)
        commandline.close()
        with open(dir_rnd_nam_link) as myfile:
            link_open = myfile.read()
        bot.send_message(chat_id=update.message.chat_id, text='%s\n🌀 طول عمر لینک 6 ساعت میباشد.\n\n/restart' %(link_open),
                         reply_markup=ReplyKeyboardRemove())
        os.remove(down_audio)
        os.remove(dir_rnd_nam_link)
        subprocess.Popen(
            'start cmd.exe /c "timeout 21600 & mega-rm -r \'%s\'"' % (rnd_nam_audio),
            shell=True)
    else:
        bot.send_chat_action(chat_id=update.message.chat_id, action=telegram.ChatAction.TYPING)
        message.reply_text('🚫 متاسفم فایل مورد نظر شما پشتیبانی نمیشود.'
                           '\n/restart',
                           reply_markup=ReplyKeyboardRemove())

    return RESTART


def uploader(bot, update):
    bot.send_chat_action(chat_id=update.message.chat_id, action=telegram.ChatAction.TYPING)
    user = update.message.from_user
    logger.info("Link of %s: %s", user.first_name, update.message.text)
    update.message.reply_text('🌀 لینک مورد نظر خود را ارسال نمایید.'
                              '\n/restart',
                              reply_markup=ReplyKeyboardRemove())

    return UPLOADING


@run_async
def uploading(bot, update):
    global final_name
    user = update.message.from_user
    logger.info("User %s did send a Link.", user.first_name)
    try:
        response = requests.get(update.message.text)
        if response.status_code == 200:
            link = update.message.text
            cwd = os.getcwd()
            dir_up = cwd + '\\tmp_up'
            dir_files = dir_up + '\\*'
            bot.send_chat_action(chat_id=update.message.chat_id, action=telegram.ChatAction.TYPING)
            update.message.reply_text('↙️ فایل مورد نظر در حال دانلود از آدرس فرستاده شده میبباشد, لطفا صبور باشید...')
            wget.download(link, dir_up)
            file_lists = glob.glob(dir_files)
            file_last = max(file_lists, key=os.path.getctime)
            cout_dir = file_last.count('\\')
            final_name = file_last.split('\\')[cout_dir].split(' ')[0]
            file_dir = dir_up + '\\' + final_name
            bot.send_chat_action(chat_id=update.message.chat_id, action=telegram.ChatAction.UPLOAD_DOCUMENT)
            update.message.reply_text('↖️ فایل مورد نظر در حال آپلود بر روی تلگرام بات میبباشد, لطفا صبور باشید...')
            bot.send_document(chat_id=update.message.chat_id, document=open(file_dir, 'rb'),
                              caption='/restart')
            os.remove(file_dir)
    except requests.exceptions.MissingSchema:
        update.message.reply_text('‼️ لینک شما معتبر نمیباشد, لطفا اصلاح نمایید.')

    return RESTART


def restart(bot, update):
    bot.send_chat_action(chat_id=update.message.chat_id, action=telegram.ChatAction.TYPING)
    user = update.message.from_user
    logger.info("User %s restarted the bot.", user.first_name)
    reply_keyboard = [['Downloader', 'Uploader'],
                      ['Admin']]
    update.message.reply_text(
        text="""⤴️ گزینه Downloader به منظور ساخت لینک از فایل Forward شده شما سرویس میدهد.

⤵️ گزینه Uploader به منظور آپلود انواع فایل ها بر روی سرور تلگرام میباشد.

🔄 برای استفاده دوباره از ربات گزینه restart را کلیک کنید.

/restart""",
        reply_markup=ReplyKeyboardMarkup(reply_keyboard, one_time_keyboard=True))

    return DOWN_UP


def admin(bot, update):
    bot.send_chat_action(chat_id=update.message.chat_id, action=telegram.ChatAction.TYPING)
    user = update.message.from_user
    logger.info("User %s admin the contact.", user.first_name)
    update.message.reply_text('❇️ پیغام خود را برای ادمین بنویسید و صبور باشید تا ادمین ربات را چک و پاسخ شما را ارسال نماید.'
                              '\n/restart',
                              reply_markup=ReplyKeyboardRemove())

    return RESTART


def error(bot, update, error):
    logger.warning('Update "%s" caused error "%s"', update, error)


def main():
    updater = Updater('Token')
    dp = updater.dispatcher
    conv_handler = ConversationHandler(
        entry_points=[CommandHandler('start', start)],

        states={
            DOWN_UP: [RegexHandler('^Downloader$', downloader),
                      RegexHandler('^Uploader$', uploader),
                      RegexHandler('^Admin$', admin)],

            DOWNLOADING: [MessageHandler(Filters.forwarded & (Filters.document | Filters.photo | Filters.audio | Filters.video), downloading)],

            UPLOADING: [MessageHandler(Filters.text & (Filters.entity(MessageEntity.URL) | Filters.entity(MessageEntity.TEXT_LINK)), uploading)],

            RESTART: [CommandHandler('restart', restart)]
        },

        fallbacks=[CommandHandler('restart', restart)]
    )

    dp.add_handler(conv_handler)
    dp.add_error_handler(error)
    updater.start_polling()
    updater.idle()


if __name__ == '__main__':
    main()
