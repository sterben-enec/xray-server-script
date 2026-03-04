nano /usr/local/sbin/xray-tun-policy.sh


1️⃣ Убираем ExecStartPost из xray

Сначала удалим override, который ломает запуск:

rm -f /etc/systemd/system/xray.service.d/20-policy.conf

Перечитаем systemd:

systemctl daemon-reload
systemctl restart xray

Проверка:

systemctl status xray --no-pager

Xray должен снова нормально стартовать.

2️⃣ Создаём отдельный сервис для iptables

Создай сервис:

nano /etc/systemd/system/xray-routing.service

Вставь:

[Unit]
Description=Xray Transparent Routing Policy
After=network.target xray.service
Requires=xray.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/xray-tun-policy.sh
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
3️⃣ Включаем автозапуск
systemctl daemon-reload
systemctl enable xray-routing.service
systemctl start xray-routing.service
