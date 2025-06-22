#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VirusTotal URL Xavfsizlik Tekshiruvchisi
Havola xavfsizligini tekshirish uchun VirusTotal API-dan foydalanadi
"""

import requests
import time
import base64
import json
import sys
from datetime import datetime
from typing import Dict, Optional, Tuple
import re


class Colors:
    """Terminal ranglari uchun ANSI kodlari"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'


class VirusTotalScanner:
    """VirusTotal API orqali URL xavfsizligini tekshiruvchi sinf"""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"x-apikey": api_key}
        self.base_url = "https://www.virustotal.com/api/v3"

    def _print_colored(self, message: str, color: str = Colors.WHITE) -> None:
        """Rangli matn chiqarish"""
        print(f"{color}{message}{Colors.END}")

    def _print_banner(self) -> None:
        """Dastur banneri"""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════╗
║                VirusTotal URL Checker                    ║
║              Havola Xavfsizlik Tekshiruvchisi            ║
╚══════════════════════════════════════════════════════════╝
{Colors.END}
        """
        print(banner)

    def _validate_url(self, url: str) -> bool:
        """URL formatini tekshirish"""
        url_pattern = re.compile(
            r'^https?://'  # http:// yoki https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domen
            r'localhost|'  # localhost
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP manzil
            r'(?::\d+)?'  # port (ixtiyoriy)
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        return url_pattern.match(url) is not None

    def _encode_url(self, url: str) -> str:
        """URL ni base64 formatiga kodlash"""
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    def _submit_url(self, url: str) -> bool:
        """URL ni VirusTotal'ga yuborish"""
        self._print_colored("📨 URL VirusTotal'ga yuborilmoqda...", Colors.BLUE)

        try:
            response = requests.post(
                f"{self.base_url}/urls",
                headers=self.headers,
                data={"url": url},
                timeout=30
            )

            if response.status_code == 200:
                self._print_colored("✅ URL muvaffaqiyatli yuborildi!", Colors.GREEN)
                return True
            else:
                self._print_colored(f"❌ Xatolik: {response.status_code} - {response.text}", Colors.RED)
                return False

        except requests.exceptions.RequestException as e:
            self._print_colored(f"❌ Tarmoq xatosi: {str(e)}", Colors.RED)
            return False

    def _get_url_report(self, url: str, max_retries: int = 5) -> Optional[Dict]:
        """URL tahlil natijasini olish"""
        url_id = self._encode_url(url)
        report_url = f"{self.base_url}/urls/{url_id}"

        for attempt in range(max_retries):
            try:
                self._print_colored(f"🔄 Natijani olish urinishi {attempt + 1}/{max_retries}...", Colors.YELLOW)

                response = requests.get(report_url, headers=self.headers, timeout=30)

                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 404:
                    self._print_colored("⏳ Tahlil hali tugamagan, kutilmoqda...", Colors.YELLOW)
                    time.sleep(10)
                else:
                    self._print_colored(f"❌ Xatolik: {response.status_code}", Colors.RED)
                    time.sleep(5)

            except requests.exceptions.RequestException as e:
                self._print_colored(f"❌ Tarmoq xatosi: {str(e)}", Colors.RED)
                time.sleep(5)

        return None

    def _analyze_results(self, data: Dict) -> Tuple[str, str]:
        """Natijalarni tahlil qilish va xulosa chiqarish"""
        attributes = data['data']['attributes']
        stats = attributes['last_analysis_stats']

        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        harmless = stats.get('harmless', 0)
        undetected = stats.get('undetected', 0)
        timeout = stats.get('timeout', 0)

        total_scans = malicious + suspicious + harmless + undetected + timeout

        # Xavfsizlik darajasini aniqlash
        if malicious > 0:
            if malicious >= 3:
                risk_level = "YUQORI XAVF"
                risk_color = Colors.RED
            else:
                risk_level = "O'RTACHA XAVF"
                risk_color = Colors.YELLOW
        elif suspicious > 0:
            risk_level = "SHUBHALI"
            risk_color = Colors.YELLOW
        else:
            risk_level = "XAVFSIZ"
            risk_color = Colors.GREEN

        return risk_level, risk_color

    def _print_detailed_results(self, url: str, data: Dict) -> None:
        """Batafsil natijalarni chiqarish"""
        attributes = data['data']['attributes']
        stats = attributes['last_analysis_stats']

        # Asosiy statistika
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        harmless = stats.get('harmless', 0)
        undetected = stats.get('undetected', 0)
        timeout = stats.get('timeout', 0)

        total_scans = malicious + suspicious + harmless + undetected + timeout

        # Xavfsizlik darajasi
        risk_level, risk_color = self._analyze_results(data)

        # Natijalarni chiqarish
        print(f"\n{Colors.BOLD}{'=' * 60}{Colors.END}")
        self._print_colored(f"🔍 TAHLIL NATIJALARI", Colors.CYAN + Colors.BOLD)
        print(f"{Colors.BOLD}{'=' * 60}{Colors.END}")

        self._print_colored(f"🌐 URL: {url}", Colors.WHITE)
        self._print_colored(f"📅 Tekshirilgan vaqt: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", Colors.WHITE)
        self._print_colored(f"🔢 Jami skanlar: {total_scans}", Colors.WHITE)

        print(f"\n{Colors.BOLD}📊 STATISTIKA:{Colors.END}")
        self._print_colored(f"  🔴 Xavfli (malicious):     {malicious:>3}",
                            Colors.RED if malicious > 0 else Colors.WHITE)
        self._print_colored(f"  🟡 Shubhali (suspicious):  {suspicious:>3}",
                            Colors.YELLOW if suspicious > 0 else Colors.WHITE)
        self._print_colored(f"  🟢 Xavfsiz (harmless):     {harmless:>3}", Colors.GREEN)
        self._print_colored(f"  ⚪ Aniqlanmagan:           {undetected:>3}", Colors.WHITE)
        self._print_colored(f"  ⏱️ Vaqt tugadi:             {timeout:>3}", Colors.WHITE)

        # Xavfsizlik darajasi
        print(f"\n{Colors.BOLD}🛡️ XAVFSIZLIK DARAJASI:{Colors.END}")
        self._print_colored(f"  {risk_level}", risk_color + Colors.BOLD)

        # Tavsiyalar
        print(f"\n{Colors.BOLD}💡 TAVSIYALAR:{Colors.END}")
        if malicious > 0:
            self._print_colored("  ⚠️ Bu havolani ochMANG! Malware yoki phishing bo'lishi mumkin.", Colors.RED)
            self._print_colored("  🔒 Kompyuteringizni antivirus bilan tekshiring.", Colors.RED)
        elif suspicious > 0:
            self._print_colored("  ⚠️ Ehtiyot bo'ling! Ba'zi antivirus dasturlari shubha bildirmoqda.", Colors.YELLOW)
            self._print_colored("  🔍 Qo'shimcha tekshiruv o'tkazing.", Colors.YELLOW)
        else:
            self._print_colored("  ✅ Havola xavfsiz ko'rinadi, lekin doimo ehtiyot bo'ling.", Colors.GREEN)

        # Qo'shimcha ma'lumotlar
        if 'last_analysis_date' in attributes:
            last_scan = datetime.fromtimestamp(attributes['last_analysis_date'])
            self._print_colored(f"\n📅 Oxirgi tahlil: {last_scan.strftime('%Y-%m-%d %H:%M:%S')}", Colors.WHITE)

        print(f"\n{Colors.BOLD}{'=' * 60}{Colors.END}")

    def scan_url(self, url: str) -> bool:
        """Asosiy URL tekshirish funksiyasi"""
        # URL formatini tekshirish
        if not self._validate_url(url):
            self._print_colored("❌ Noto'g'ri URL formati! URL http:// yoki https:// bilan boshlanishi kerak.",
                                Colors.RED)
            return False

        # URL ni yuborish
        if not self._submit_url(url):
            return False

        # Natijani olish
        self._print_colored("⏳ Tahlil jarayoni davom etmoqda, iltimos kuting...", Colors.YELLOW)
        data = self._get_url_report(url)

        if data is None:
            self._print_colored("❌ Tahlil natijasini olishda xatolik yuz berdi.", Colors.RED)
            return False

        # Natijalarni chiqarish
        self._print_detailed_results(url, data)
        return True

    def interactive_mode(self) -> None:
        """Interaktiv rejim"""
        self._print_banner()

        while True:
            try:
                print(f"\n{Colors.BOLD}Variantlar:{Colors.END}")
                print("1. URL tekshirish")
                print("2. Chiqish")

                choice = input(f"\n{Colors.CYAN}Tanlovingizni kiriting (1-2): {Colors.END}").strip()

                if choice == "1":
                    url = input(f"\n{Colors.CYAN}🔗 Tekshirish uchun URL kiriting: {Colors.END}").strip()
                    if url:
                        print()
                        self.scan_url(url)
                    else:
                        self._print_colored("❌ URL kiritilmadi!", Colors.RED)

                elif choice == "2":
                    self._print_colored("\n👋 Xayr! Xavfsiz qoling!", Colors.GREEN)
                    break

                else:
                    self._print_colored("❌ Noto'g'ri tanlov! Iltimos 1 yoki 2 ni tanlang.", Colors.RED)

            except KeyboardInterrupt:
                self._print_colored("\n\n👋 Dastur to'xtatildi. Xayr!", Colors.YELLOW)
                break
            except Exception as e:
                self._print_colored(f"❌ Kutilmagan xatolik: {str(e)}", Colors.RED)


def main():
    """Asosiy funksiya"""
    # API kalitini tekshirish
    API_KEY = "09609d89a28843cf15fc635fe7d36a8a2d35033ea2694914f32965883f61aceb"

    if not API_KEY or len(API_KEY) < 32:
        print(f"{Colors.RED}❌ Noto'g'ri API kalit! VirusTotal API kalitingizni tekshiring.{Colors.END}")
        sys.exit(1)

    # Scanner yaratish va ishga tushirish
    scanner = VirusTotalScanner(API_KEY)

    # Argumentlar bilan ishlatish
    if len(sys.argv) > 1:
        url = sys.argv[1]
        scanner._print_banner()
        scanner.scan_url(url)
    else:
        # Interaktiv rejim
        scanner.interactive_mode()


if __name__ == "__main__":
    main()