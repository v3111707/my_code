#!/usr/bin/env python3

import datetime
import typer
import random
import json
import os
import sys
import re
import pymsteams
import logging
from cmdbng import Client as CmdbClient
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from smtplib import SMTP

PERIODS2MIN = {'month': 43800,
               'year': 525600,
               'week': 10080}

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])
TIME_FORMAT = '%Y-%m-%dT%H:%M:%S'
START_EVERY_MIN = 30
DB_PATH = '~/chaosmonkey.json'
CMDB_URL = 'https://*****.net'

app = typer.Typer(add_completion=False)

SUBJECT = 'The {server} will be restarted at {time}(UTC).'
MESSAGE = SUBJECT + '\nSchedule name: {sname}, schedule notes: {snotes}\nTo cancel the reboot, connect via ssh to {server} and run "touch /srv/racoon/cancel/any_file_name"'


def init_logger(debug: bool):
    logger = logging.getLogger('main')
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(logging.Formatter('%(asctime)s - %(name)s: %(message)s'))
    logger.addHandler(sh)
    if debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)


def get_date(add_mins: int = None):
    if add_mins:
        date = datetime.datetime.now().date() + datetime.timedelta(minutes=add_mins)
    else:
        date = datetime.datetime.now().date()
    return date


def str2date(date: str):
    return datetime.datetime.strptime(date, '%Y-%m-%d').date()


def str2time(date: str):
    return datetime.datetime.strptime(date, TIME_FORMAT)


def time2str(time: datetime):
    return time.strftime(TIME_FORMAT)


def add_min(time: datetime, mins: int):
    return time + datetime.timedelta(minutes=mins)


def is_night(time: datetime, start: int = 23, end: int = 6):
    if end <= time.hour < start:
        return False
    return True


def check_email_address(email):
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    if (re.fullmatch(regex, email)):
        return True
    else:
        return False


def send_teams_msg(url, msg):
    teams_channel = pymsteams.connectorcard(url)
    teams_channel.text(msg)
    teams_channel.send()


def send_mail(send_to, text, subj, mail_from="chaosmonkey" + '@' + os.uname()[1]):
    msg = MIMEMultipart()
    msg['From'] = mail_from
    msg['To'] = send_to
    msg['Subject'] = subj
    body = text
    msg.attach(MIMEText(body, 'plain'))
    server = SMTP()
    text = msg.as_string()
    if isinstance(send_to, str):
        send_to = [m.strip() for m in send_to.split(',')]
    server.connect()
    server.sendmail(mail_from, send_to, text)
    server.quit()


class ChaosMonkey:
    logger_name = 'main.ChaosMonkey'
    cmdb_link_repo_name = 'servers_random_reboot_link'
    cmdb_schedule_repo_name = 'servers_random_reboot_schedule'
    schedule_offset = 90  # min
    stime = None  # Start time

    def __init__(self, db_path: str, cmdb_url: str, cmdb_username: str, cmdb_password: str):
        self.logger = logging.getLogger(self.logger_name)
        self.db_path = os.path.expanduser(db_path)
        self.schedules = {}
        self._load_db()
        self.cmdbng = CmdbClient(url=cmdb_url,
                                 username=cmdb_username,
                                 password=cmdb_password)
        self.cmdbng.introspect()

    def run(self):
        self.stime = datetime.datetime.now()
        self.logger.info(f'self.stime: {self.stime}')
        self._generate_schedules()
        self._sync_schedules_with_cmdb()
        self._send_notifications()

    def _send_notifications(self):
        cmdb_links_repo = self.cmdbng.repo_by_name(self.cmdb_link_repo_name)
        columns = ['next_reboot', {'name': 'server', 'columns': ['hostname']},
                   {'name': 'servers_random_reboot_schedule', 'columns': ['name', 'notifications', 'notes']}]

        where = {'$and': [{'next_reboot': {'$gte': time2str(self.stime + datetime.timedelta(minutes=60))}},
                          {'next_reboot': {'$lt': time2str(self.stime + datetime.timedelta(minutes=60 + START_EVERY_MIN))}}]}

        servers_reboot = cmdb_links_repo.select(columns=columns, where=where)
        self.logger.debug(f'_send_notifications : servers_reboot = {servers_reboot} ')
        for s in servers_reboot:
            if s['servers_random_reboot_schedule']['notifications']:
                for notification in s['servers_random_reboot_schedule']['notifications'].split(','):
                    notification = notification.strip()
                    msg = MESSAGE.format(server=s['server']['hostname'],
                                         sname=s['servers_random_reboot_schedule']['name'],
                                         snotes=s['servers_random_reboot_schedule']['notes'],
                                         time=s['next_reboot'])
                    if check_email_address(notification):
                        self.logger.info(f'Send mail to {notification}')
                        try:
                            send_mail(send_to=notification,
                                      text=msg,
                                      subj=SUBJECT.format(server=s['server']['hostname'], time=s['next_reboot']))
                        except Exception as e:
                            self.logger.error(f'Error while sending mail send_to={notification}, text={msg}')
                            self.logger.exception(e)
                    elif 'https://corpwargaming.webhook.office.com' in notification:
                        try:
                            send_teams_msg(url=notification,
                                           msg=msg)
                        except Exception as e:
                            self.logger.error(f'Error while sending teams message url={notification}, msg={msg}')
                            self.logger.exception(e)
                    else:
                        self.logger.warning(f'Unknown notification:{notification}')

    def _get_next_scheduled_reboot(self, schedule_id: str, servers_link_id: int):
        schedule = self.schedules.get(schedule_id)
        if schedule:
            server_reboots = [i['reboot_time'] for i in schedule['scheduled_reboots'] if
                              i['server_link_id'] == servers_link_id]
            for reboot_time in sorted(server_reboots):
                if str2time(reboot_time) > self.stime:
                    return reboot_time
        else:
            self.logger.debug(f'The schedule with id {schedule_id} not found')
        return None

    def _sync_schedules_with_cmdb(self):
        self.logger.debug('start  _sync_reboot_time_with_cmdb')
        cmdb_links_repo = self.cmdbng.repo_by_name(self.cmdb_link_repo_name)
        servers_reboot_link = cmdb_links_repo.select()
        for sl in servers_reboot_link:
            next_reboot_time = self._get_next_scheduled_reboot(str(sl['servers_random_reboot_schedule_id']), sl['id'])
            if sl['next_reboot'] and str2time(sl['next_reboot']) < self.stime:
                self.logger.info(f'update last_reboot {sl["last_reboot"]} -> {sl["next_reboot"]} for id {sl["id"]} ')
                sl['last_reboot'] = sl['next_reboot']
            if sl['next_reboot'] != next_reboot_time:
                self.logger.info(f'update next_reboot {sl["next_reboot"]} -> {next_reboot_time} for id {sl["id"]} ')
                sl['next_reboot'] = next_reboot_time
            if sl.changed:
                sl.save()

    def _compare_schedules(self, schedule_one, schedule_two) -> bool:
        compare_fields = ['period', 'start_from', 'times']
        for field in compare_fields:
            if schedule_one.get(field) != schedule_two.get(field):
                self.logger.debug(f'schedules are not equal by {field}')
                return False
        if len(schedule_one.get('servers_random_reboot_links')) != len(schedule_two.get('servers_random_reboot_links')):
            self.logger.debug('schedules are not equal by len(servers_random_reboot_links)')
            return False
        servers_links_one = sorted(schedule_one.get('servers_random_reboot_links'), key=lambda d: d['id'])
        servers_links_two = sorted(schedule_two.get('servers_random_reboot_links'), key=lambda d: d['id'])
        pairs = zip(servers_links_one, servers_links_two)
        for x, y in pairs:
            if x['id'] != y['id'] or x['start_from'] != y['start_from']:
                self.logger.debug('schedules are not equal, different servers_random_reboot_links ')
                return False
        return True

    def _generate_schedules(self):
        cmdb_schedules = self._get_data_from_cmdb()
        for cmdb_schedule in cmdb_schedules:
            cmdb_schedule_id = str(cmdb_schedule['id'])
            self.logger.debug(f"processing {cmdb_schedule_id}")
            if str2date(cmdb_schedule['start_from']) > get_date():
                self.logger.info(
                    f" Skip the schedule with id {cmdb_schedule_id} and notes {cmdb_schedule['notes']} due to start_from {cmdb_schedule['start_from']}")
                self._remove_schedule(cmdb_schedule_id)
                continue
            if not [i for i in cmdb_schedule['servers_random_reboot_links'] if
                    i['start_from'] is None or get_date(add_mins=PERIODS2MIN[cmdb_schedule['period']]) >= str2date(
                        i['start_from'])]:
                self.logger.info(
                    f" Skip the schedule with id {cmdb_schedule_id} and notes {cmdb_schedule['notes']} due to no server for reboot")
                self._remove_schedule(cmdb_schedule_id)
                continue
            schedule = self.schedules.get(cmdb_schedule_id)
            if not schedule:
                self.logger.info(f"Schedule not found in internal db, create a new one")
                self._create_schedule(cmdb_schedule)
            elif not self._compare_schedules(cmdb_schedule, schedule):
                self.logger.info(f"The Schedule was changed in cmdb, re-create.")
                self._create_schedule(cmdb_schedule)
            elif get_date(add_mins=-PERIODS2MIN[schedule['period']]) >= str2date(schedule['created']):
                self.logger.info(f"Schedule out of date, create a new one")
                self._create_schedule(cmdb_schedule)

        for s in set(self.schedules.keys()) - set([str(i['id']) for i in cmdb_schedules]):
            self._remove_schedule(s)

    def _remove_schedule(self, schedule_id: str):
        if self.schedules.get(schedule_id):
            self.logger.info(f'Remove schedule with id {schedule_id}')
            _ = self.schedules.pop(schedule_id)
            self._save_db()

    def _create_schedule(self, cmdb_schedule):
        cmdb_schedule_id = str(cmdb_schedule['id'])
        scheduled_reboots = self._generate_schedule(period=cmdb_schedule['period'],
                                                    times=cmdb_schedule['times'],
                                                    server_links=cmdb_schedule['servers_random_reboot_links'],
                                                    not_night=True)
        fields_for_save = ['period', 'start_from', 'times', 'servers_random_reboot_links']
        current_schedule = {i: j for i, j in cmdb_schedule.items() if i in fields_for_save}
        current_schedule['scheduled_reboots'] = scheduled_reboots
        current_schedule['created'] = get_date().strftime('%Y-%m-%d')
        self.schedules[cmdb_schedule_id] = current_schedule
        self._save_db()

    def _generate_schedule(self, period: str, times: int, server_links: list, not_night: bool = False):
        next_server = self._get_next_server(server_links=server_links)
        _ = next_server.send(None)
        schedule = []
        self.logger.info(f'Start generate schedule period={period}, times={times}, servers count={len(server_links)}')
        for start, end in self._get_intervals(period, times):
            start_time = add_min(self.stime, self.schedule_offset + start)
            end_time = add_min(self.stime, self.schedule_offset + end)
            if not_night:
                if is_night(start_time) and is_night(end_time):
                    self.logger.warning(
                        f'not_night is True and is_night(start_time), is_night(start_time) is True too. Skip')
                    continue
                if is_night(start_time):
                    start_time = datetime.datetime.combine(start_time.date(), datetime.time(6, 0))
                elif is_night(end_time):
                    end_time = datetime.datetime.combine(end_time.date(), datetime.time(23, 0))
                while True:
                    reboot_time = self._random_date(start_time, end_time)
                    if not is_night(reboot_time):
                        break
            else:
                reboot_time = self._random_date(start_time, end_time)
            server_link_id = next_server.send(reboot_time)
            self.logger.info(f'reboot_time f{reboot_time} for server_link_id {server_link_id}')
            schedule.append({'server_link_id': server_link_id, 'reboot_time': reboot_time.strftime(TIME_FORMAT)})
        return schedule

    def _random_date(self, start, end):
        self.logger.info(f'Generate reboot time between f{start} and f{end}')
        delta = end - start
        int_delta = (delta.days * 24 * 60 * 60) + delta.seconds
        random_second = random.randrange(int_delta)
        return self._round_datetime(start + datetime.timedelta(seconds=random_second))

    def _round_datetime(self, dt: datetime, to: int = 30):
        delta = datetime.timedelta(minutes=to)
        rounded_dt = dt + (datetime.datetime.min - dt) % delta
        self.logger.info(f'{dt} was rounded off to {rounded_dt}')
        return rounded_dt

    @staticmethod
    def _get_intervals(period: str, quantity: int):
        mins = PERIODS2MIN[period]
        period_range = int(mins / quantity)
        for i in range(quantity):
            yield period_range * i, period_range * (i + 1)

    def _get_next_server(self, server_links: list):
        sl_queue = [i for i in server_links if i['last_reboot'] is None]
        sl_queue += sorted([i for i in server_links if i['last_reboot']], key=lambda i: i['last_reboot'])
        date = yield None
        while True:
            sl = None
            for i in range(len(sl_queue)):
                if sl_queue[i]['start_from'] is None or date.date() >= str2date(sl_queue[i]['start_from']):
                    sl = sl_queue.pop(i)
                    sl_queue.append(sl)
                    break
            if sl:
                date = yield sl['id']
            else:
                self.logger.warning(f'Not found suitable server for reboot date {date}')
                date = yield None

    def _get_data_from_cmdb(self):
        cmdb_schedule = self.cmdbng.repo_by_name(self.cmdb_schedule_repo_name)
        search_columns = ['id', 'period', 'start_from', 'times', 'notes',
                          {'name': 'servers_random_reboot_links',
                           'columns': ['id', 'next_reboot', 'last_reboot', 'start_from']}]
        resp = cmdb_schedule.select(columns=search_columns)
        self.logger.debug(f'cmdb resp: {resp}')
        return resp

    def _save_db(self):
        with open(self.db_path, 'w') as fp:
            json.dump(self.schedules, fp)

    def _load_db(self):
        try:
            with open(self.db_path, 'r') as fp:
                self.schedules = json.load(fp)
        except Exception as e:
            self.logger.warning(f'Error while open {self.db_path}: {e}')


@app.command(context_settings=CONTEXT_SETTINGS)
def main(debug: bool = typer.Option(False, '-d', '--debug', show_default=True),
         db_path: str = DB_PATH):
    init_logger(debug=debug)
    logger = logging.getLogger('main')
    logger.debug('Running with --debug flag')
    сonfig = {}
    chaos_monkey = ChaosMonkey(db_path=db_path,
                               cmdb_url=CMDB_URL,
                               cmdb_username=сonfig['username'],
                               cmdb_password=сonfig['password'])
    chaos_monkey.run()


if __name__ == '__main__':
    app()
