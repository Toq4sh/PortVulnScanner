import socket
import argparse
from colorama import init, Fore

# Инициализируем Colorama для цветного вывода в Windows тоже
init(autoreset=True)

def scan_port(target, port, timeout=1.0):
    """
    Пытается подключиться к порту и проверяет на базовые уязвимости.
    """
    try:
        # Создаем сокет и устанавливаем таймаут
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        # Пытаемся подключиться
        result = sock.connect_ex((target, port))

        if result == 0:  # Порт открыт
            service = get_service_name(port)  # Пытаемся узнать сервис
            print(Fore.GREEN + f"[+] Порт {port}/tcp открыт - Сервис: {service}")

            # БАЗОВЫЕ ПРОВЕРКИ НА УЯЗВИМОСТИ (ЗДЕСЬ ТВОЙ ПОТЕНЦИАЛ ДЛЯ РОСТА!)
            check_common_vulns(target, port, service)

        sock.close()

    except socket.error:
        print(Fore.RED + f"[-] Ошибка при сканировании порта {port}")
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Сканирование прервано пользователем.")
        exit()

def get_service_name(port):
    """
    Пытается получить название сервиса по стандартному порту (упрощенно).
    """
    try:
        return socket.getservbyport(port, 'tcp').upper()
    except OSError:
        return "unknown"

def check_common_vulns(target, port, service):
    """
    Простейшие проверки на ОЧЕНЬ известные уязвимости по порту/сервису.
    """
    # Пример 1: HTTP/HTTPS - Проверка на простой заголовок Server (информация)
    if service in ['HTTP', 'HTTPS']:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((target, port))
            s.send(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            response = s.recv(1024).decode('utf-8', errors='ignore')
            s.close()

            if 'Server:' in response:
                server_header = response.split('Server:')[1].split('\r\n')[0].strip()
                print(Fore.CYAN + f"    [i] HTTP Server: {server_header}")
                # Здесь могла бы быть проверка на известные уязвимые версии
                # if "Apache/2.2.15" in server_header:
                #    print(Fore.RED + "    [!] ВОЗМОЖНА УЯЗВИМОСТЬ: CVE-XXXX-XXXX (Apache 2.2.15)")

        except:
            pass

    # Пример 2: FTP - Анонимный вход (очень распространенная ошибка)
    elif service == 'FTP':
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((target, port))
            banner = s.recv(1024).decode('utf-8', errors='ignore')
            s.send(b"USER anonymous\r\n")
            response_user = s.recv(1024).decode('utf-8', errors='ignore')
            s.send(b"PASS anonymous@example.com\r\n")
            response_pass = s.recv(1024).decode('utf-8', errors='ignore')
            s.close()

            if "230" in response_pass:  # Код 230 = Успешный логин
                print(Fore.RED + "    [!] УЯЗВИМОСТЬ: Разрешен анонимный вход в FTP!")
                print(Fore.RED + f"    [!] Баннер: {banner.strip()}")

        except:
            pass

    # Пример 3: SSH - Просто вывод баннера (информация)
    elif service == 'SSH':
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((target, port))
            banner = s.recv(1024).decode('utf-8', errors='ignore')
            s.close()
            print(Fore.CYAN + f"    [i] SSH Баннер: {banner.strip()}")
            # Здесь могла бы быть проверка на известные уязвимые версии SSH
        except:
            pass

    # ДОБАВЛЯЙ ДРУГИЕ ПРОВЕРКИ ЗДЕСЬ! (Для Telnet, SMB, устаревших версий и т.д.)

def main():
    # Парсим аргументы командной строки
    parser = argparse.ArgumentParser(description='Простой сканер портов с базовой проверкой уязвимостей (УЧЕБНЫЙ ПРОЕКТ)')
    parser.add_argument('target', type=str, help='Целевой IP-адрес или хост')
    parser.add_argument('-p', '--ports', type=str, default='1-1024',
                        help='Диапазон портов для сканирования (например, 80,443 или 20-100)')
    args = parser.parse_args()

    # Обрабатываем целевой хост
    target = args.target
    try:
        target_ip = socket.gethostbyname(target)  # Преобразуем хост в IP, если нужно
    except socket.gaierror:
        print(Fore.RED + f"[-] Не удается разрешить '{target}'. Проверьте имя хоста/IP.")
        exit()

    # Обрабатываем диапазон портов
    ports = []
    if '-' in args.ports:
        start, end = map(int, args.ports.split('-'))
        ports = range(start, end + 1)
    elif ',' in args.ports:
        ports = map(int, args.ports.split(','))
    else:
        ports = [int(args.ports)]

    # Выводим стартовую информацию
    print(Fore.YELLOW + f"[*] Начинаем сканирование целевого хоста: {target} ({target_ip})")
    print(Fore.YELLOW + f"[*] Диапазон портов: {args.ports}\n")

    # Сканируем порты по одному
    for port in ports:
        scan_port(target_ip, port)

    print(Fore.YELLOW + "\n[*] Сканирование завершено.")

if __name__ == "__main__":
    main()
