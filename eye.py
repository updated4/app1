#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import threading
from datetime import datetime
from collections import deque
from scapy.all import *
import curses
from curses import wrapper
import argparse
import signal
import binascii

class TerminalPacketSniffer:
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.packets = deque(maxlen=1000)
        self.is_running = False
        self.sniff_thread = None
        self.lock = threading.Lock()
        
        # Scrolling support
        self.scroll_offset = 0
        self.visible_rows = 0
        self.selected_row = 0
        self.view_mode = "list"  # list, detail, hex, tcp_analysis
        self.detail_packet_idx = -1
        
        # Statistics
        self.stats = {
            'total': 0, 'tcp': 0, 'udp': 0, 'icmp': 0, 
            'http': 0, 'https': 0, 'dns': 0, 'arp': 0
        }
        
        self.filter_exp = ""
        self.interface = None
        
        # Performance settings
        self.last_update = 0
        self.update_interval = 0.05
        
        # 🎨 Color scheme
        curses.start_color()
        curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)    # Header
        curses.init_pair(2, curses.COLOR_CYAN, curses.COLOR_BLACK)     # Packet info
        curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)   # Stats
        curses.init_pair(4, curses.COLOR_RED, curses.COLOR_BLACK)      # Warning
        curses.init_pair(5, curses.COLOR_MAGENTA, curses.COLOR_BLACK)  # Protocol
        curses.init_pair(6, curses.COLOR_BLUE, curses.COLOR_BLACK)     # Timestamp
        curses.init_pair(7, curses.COLOR_WHITE, curses.COLOR_BLACK)    # Normal text
        curses.init_pair(8, curses.COLOR_BLACK, curses.COLOR_GREEN)    # Highlight
        curses.init_pair(9, curses.COLOR_WHITE, curses.COLOR_RED)      # Error
        curses.init_pair(10, curses.COLOR_BLACK, curses.COLOR_CYAN)    # Selected row
        curses.init_pair(11, curses.COLOR_WHITE, curses.COLOR_BLUE)    # Detail header
        curses.init_pair(12, curses.COLOR_GREEN, curses.COLOR_BLACK)   # Success
        curses.init_pair(13, curses.COLOR_MAGENTA, curses.COLOR_BLACK) # Analysis
        
        # 🐍 Animal emojis and symbols
        self.animals = {
            'snake': '🐍', 'fox': '🦊', 'owl': '🦉', 'wolf': '🐺',
            'lion': '🦁', 'tiger': '🐯', 'bear': '🐻', 'panda': '🐼',
            'cat': '🐱', 'dog': '🐶', 'rabbit': '🐰', 'mouse': '🐭'
        }
        
        self.protocols = {
            'TCP': '🔗', 'UDP': '📡', 'ICMP': '🔊', 'ARP': '🔄',
            'HTTP': '🌐', 'HTTPS': '🔒', 'DNS': '🔍', 'Unknown': '❓'
        }
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
    def signal_handler(self, signum, frame):
        """Handle termination signals gracefully"""
        self.stop_sniffing()
        curses.endwin()
        print(f"\n{self.animals['snake']} Sniffer stopped by signal {signum}")
        sys.exit(0)
        
    def draw_header(self):
        """Draw the beautiful header with animal symbols"""
        try:
            height, width = self.stdscr.getmaxyx()
            
            # 🐍 Header with animal theme
            if self.view_mode == "list":
                header_text = f" {self.animals['snake']} PYTHON PACKET SNIFFER {self.animals['fox']} "
            elif self.view_mode == "detail":
                header_text = f" {self.animals['owl']} PACKET DETAILS {self.animals['owl']} "
            elif self.view_mode == "hex":
                header_text = f" {self.animals['wolf']} HEX DUMP VIEW {self.animals['wolf']} "
            elif self.view_mode == "tcp_analysis":
                header_text = f" {self.animals['lion']} TCP ANALYSIS {self.animals['lion']} "
            
            start_x = max(0, (width - len(header_text)) // 2)
            self.stdscr.addstr(0, start_x, header_text, curses.color_pair(1) | curses.A_BOLD)
            
            # 📊 Status bar
            with self.lock:
                status = f"📊 Packets: {self.stats['total']} | "
                status += f"🔗 TCP: {self.stats['tcp']} | "
                status += f"📡 UDP: {self.stats['udp']} | "
                status += f"🔊 ICMP: {self.stats['icmp']} | "
                status += f"🌐 HTTP: {self.stats['http']} | "
                status += f"🔒 HTTPS: {self.stats['https']} | "
                status += f"🔍 DNS: {self.stats['dns']} | "
                status += f"🔄 ARP: {self.stats['arp']}"
            
            if len(status) > width - 2:
                status = status[:width-5] + "..."
                
            self.stdscr.addstr(1, 1, status, curses.color_pair(3))
            
            # 🎯 Filter info
            if self.filter_exp:
                filter_text = f"🎯 Filter: {self.filter_exp}"
                self.stdscr.addstr(2, 1, filter_text, curses.color_pair(5))
            
            # 🌐 Interface info
            if self.interface:
                iface_text = f"🌐 Interface: {self.interface}"
                self.stdscr.addstr(2, width - len(iface_text) - 1, iface_text, curses.color_pair(5))
        except curses.error:
            pass
    
    def draw_packet_list(self):
        """Draw the packet list with scrolling support"""
        try:
            height, width = self.stdscr.getmaxyx()
            self.visible_rows = height - 8
            
            # 📋 Column headers
            headers = ["#", "⏰ Time", "📤 Source", "📥 Destination", "🔌 Proto", "📏 Len", "ℹ️ Info"]
            header_line = ""
            col_widths = [4, 12, 18, 18, 8, 8, 30]
            
            for i, header in enumerate(headers):
                header_line += f"{header:<{col_widths[i]}}"
            
            if len(header_line) > width - 2:
                header_line = header_line[:width-5] + "..."
                
            self.stdscr.addstr(4, 1, header_line, curses.color_pair(1) | curses.A_BOLD)
            self.stdscr.addstr(5, 0, "─" * (width - 1), curses.color_pair(7))
            
            # 📦 Display packets with scrolling
            with self.lock:
                packets_list = list(self.packets)
                total_packets = len(packets_list)
            
            if total_packets == 0:
                # Show help message
                help_msg = f"{self.animals['cat']} No packets captured yet. Start sniffing to see packets!"
                self.stdscr.addstr(7, 2, help_msg, curses.color_pair(2))
                return
                
            # Adjust scroll offset to keep selection visible
            if self.selected_row < self.scroll_offset:
                self.scroll_offset = self.selected_row
            elif self.selected_row >= self.scroll_offset + self.visible_rows:
                self.scroll_offset = self.selected_row - self.visible_rows + 1
            
            # Ensure scroll offset is within bounds
            self.scroll_offset = max(0, min(self.scroll_offset, max(0, total_packets - self.visible_rows)))
            
            # Display visible packets
            start_idx = self.scroll_offset
            end_idx = min(start_idx + self.visible_rows, total_packets)
            
            for i in range(start_idx, end_idx):
                row = 6 + (i - start_idx)
                if row >= height - 2:
                    break
                    
                packet_info = packets_list[i]
                
                # 🎨 Highlight selected row
                if i == self.selected_row:
                    attr = curses.color_pair(10) | curses.A_BOLD
                else:
                    attr = curses.color_pair(2)
                
                # 📊 Packet data
                line = f"{packet_info['no']:<4} "
                line += f"{packet_info['time']:<12} "
                line += f"{packet_info['src']:<18.18} "
                line += f"{packet_info['dst']:<18.18} "
                line += f"{self.protocols.get(packet_info['proto'], '❓')} {packet_info['proto']:<4} "
                line += f"{packet_info['len']:<8} "
                line += f"{packet_info['info']:<30.30}"
                
                if len(line) > width - 2:
                    line = line[:width-5] + "..."
                    
                try:
                    self.stdscr.addstr(row, 1, line, attr)
                except curses.error:
                    break
                    
            # 📜 Scroll indicator
            if total_packets > self.visible_rows:
                shown_start = self.scroll_offset + 1
                shown_end = min(self.scroll_offset + self.visible_rows, total_packets)
                scroll_info = f"📋 {shown_start}-{shown_end} of {total_packets}"
                self.stdscr.addstr(height - 3, width - len(scroll_info) - 1, scroll_info, curses.color_pair(3))
                
        except curses.error:
            pass
    
    def draw_packet_detail(self):
        """Draw detailed packet information"""
        try:
            height, width = self.stdscr.getmaxyx()
            
            with self.lock:
                packets_list = list(self.packets)
            
            if not packets_list or self.detail_packet_idx < 0 or self.detail_packet_idx >= len(packets_list):
                return
                
            packet = packets_list[self.detail_packet_idx]
            packet_obj = packet.get('raw_packet')
            
            # 📋 Detail header
            detail_header = f"📋 Packet #{packet['no']} Details"
            self.stdscr.addstr(4, 1, detail_header, curses.color_pair(11) | curses.A_BOLD)
            self.stdscr.addstr(5, 0, "─" * (width - 1), curses.color_pair(7))
            
            # 📊 Basic information
            row = 6
            self.stdscr.addstr(row, 2, f"⏰ Time:     {packet['time']}", curses.color_pair(2))
            self.stdscr.addstr(row+1, 2, f"📤 Source:   {packet['src']}", curses.color_pair(2))
            self.stdscr.addstr(row+2, 2, f"📥 Destination: {packet['dst']}", curses.color_pair(2))
            self.stdscr.addstr(row+3, 2, f"🔌 Protocol: {self.protocols.get(packet['proto'], '❓')} {packet['proto']}", curses.color_pair(2))
            self.stdscr.addstr(row+4, 2, f"📏 Length:   {packet['len']} bytes", curses.color_pair(2))
            self.stdscr.addstr(row+5, 2, f"ℹ️ Info:     {packet['info']}", curses.color_pair(2))
            
            # 🔍 Protocol-specific analysis
            row += 7
            if packet_obj:
                self.stdscr.addstr(row, 2, "🔍 Protocol Analysis:", curses.color_pair(13) | curses.A_BOLD)
                row += 1
                
                # Show scapy dissected layers
                try:
                    dissected = packet_obj.show(dump=True)
                    lines = dissected.split('\n')
                    for i, line in enumerate(lines[:height-row-5]):
                        if line.strip():
                            self.stdscr.addstr(row+i, 4, line[:width-6], curses.color_pair(7))
                except:
                    self.stdscr.addstr(row, 4, "Unable to dissect packet", curses.color_pair(4))
            
        except curses.error:
            pass
    
    def draw_hex_view(self):
        """Draw hex dump of selected packet"""
        try:
            height, width = self.stdscr.getmaxyx()
            
            with self.lock:
                packets_list = list(self.packets)
            
            if not packets_list or self.detail_packet_idx < 0 or self.detail_packet_idx >= len(packets_list):
                return
                
            packet = packets_list[self.detail_packet_idx]
            packet_obj = packet.get('raw_packet')
            
            if not packet_obj:
                return
                
            # 📋 Hex view header
            hex_header = f"헥 Packet #{packet['no']} Hex Dump"
            self.stdscr.addstr(4, 1, hex_header, curses.color_pair(11) | curses.A_BOLD)
            self.stdscr.addstr(5, 0, "─" * (width - 1), curses.color_pair(7))
            
            # 📊 Convert packet to hex
            try:
                raw_bytes = bytes(packet_obj)
                hex_dump = hexdump(raw_bytes, dump=True)
                lines = hex_dump.split('\n')
                
                # Display hex dump
                start_row = 6
                for i, line in enumerate(lines[:height-start_row-3]):
                    if line.strip():
                        self.stdscr.addstr(start_row+i, 2, line[:width-4], curses.color_pair(7))
            except Exception as e:
                self.stdscr.addstr(6, 2, f"Error generating hex dump: {e}", curses.color_pair(4))
                
        except curses.error:
            pass
    
    def draw_tcp_analysis(self):
        """Draw TCP protocol analysis"""
        try:
            height, width = self.stdscr.getmaxyx()
            
            with self.lock:
                packets_list = list(self.packets)
            
            if not packets_list or self.detail_packet_idx < 0 or self.detail_packet_idx >= len(packets_list):
                return
                
            packet = packets_list[self.detail_packet_idx]
            packet_obj = packet.get('raw_packet')
            
            # 📋 TCP Analysis header
            tcp_header = f"🦁 TCP Protocol Analysis for Packet #{packet['no']}"
            self.stdscr.addstr(4, 1, tcp_header, curses.color_pair(11) | curses.A_BOLD)
            self.stdscr.addstr(5, 0, "─" * (width - 1), curses.color_pair(7))
            
            row = 6
            
            if packet_obj and TCP in packet_obj:
                tcp_layer = packet_obj[TCP]
                
                # 📊 TCP Header Information
                self.stdscr.addstr(row, 2, "🔗 TCP Header Fields:", curses.color_pair(13) | curses.A_BOLD)
                row += 1
                self.stdscr.addstr(row, 4, f"Source Port: {tcp_layer.sport}", curses.color_pair(2))
                self.stdscr.addstr(row+1, 4, f"Destination Port: {tcp_layer.dport}", curses.color_pair(2))
                self.stdscr.addstr(row+2, 4, f"Sequence Number: {tcp_layer.seq}", curses.color_pair(2))
                self.stdscr.addstr(row+3, 4, f"Acknowledgment: {tcp_layer.ack}", curses.color_pair(2))
                self.stdscr.addstr(row+4, 4, f"Data Offset: {tcp_layer.dataofs}", curses.color_pair(2))
                self.stdscr.addstr(row+5, 4, f"Reserved: {tcp_layer.reserved}", curses.color_pair(2))
                
                # 🚩 TCP Flags
                row += 7
                self.stdscr.addstr(row, 2, "🚩 TCP Flags:", curses.color_pair(13) | curses.A_BOLD)
                row += 1
                
                flags = tcp_layer.flags
                flag_descriptions = [
                    (0x01, "FIN", "No more data from sender"),
                    (0x02, "SYN", "Synchronize sequence numbers"),
                    (0x04, "RST", "Reset the connection"),
                    (0x08, "PSH", "Push function"),
                    (0x10, "ACK", "Acknowledgment field significant"),
                    (0x20, "URG", "Urgent pointer field significant"),
                    (0x40, "ECE", "ECN-Echo"),
                    (0x80, "CWR", "Congestion Window Reduced")
                ]
                
                for i, (flag, name, desc) in enumerate(flag_descriptions):
                    if flags & flag:
                        status = "✓ SET"
                        attr = curses.color_pair(12)
                    else:
                        status = "○ NOT SET"
                        attr = curses.color_pair(7)
                    self.stdscr.addstr(row+i, 4, f"{name}: {status} - {desc}", attr)
                
                row += len(flag_descriptions) + 1
                
                # 📏 Other TCP Fields
                self.stdscr.addstr(row, 2, "📏 Other TCP Fields:", curses.color_pair(13) | curses.A_BOLD)
                row += 1
                self.stdscr.addstr(row, 4, f"Window Size: {tcp_layer.window}", curses.color_pair(2))
                self.stdscr.addstr(row+1, 4, f"Checksum: 0x{tcp_layer.chksum:04x}", curses.color_pair(2))
                self.stdscr.addstr(row+2, 4, f"Urgent Pointer: {tcp_layer.urgptr}", curses.color_pair(2))
                
                # 📦 Payload Information
                row += 4
                payload = tcp_layer.payload
                if payload:
                    self.stdscr.addstr(row, 2, "📦 Payload Analysis:", curses.color_pair(13) | curses.A_BOLD)
                    row += 1
                    payload_type = type(payload).__name__
                    self.stdscr.addstr(row, 4, f"Payload Type: {payload_type}", curses.color_pair(2))
                    self.stdscr.addstr(row+1, 4, f"Payload Length: {len(payload)} bytes", curses.color_pair(2))
                    
                    # Try to decode common protocols
                    if payload_type == "Raw":
                        raw_data = bytes(payload)
                        if len(raw_data) > 0:
                            # Check for HTTP
                            if raw_data.startswith(b'GET') or raw_data.startswith(b'POST') or raw_data.startswith(b'HTTP'):
                                self.stdscr.addstr(row+2, 4, "🔍 Detected: HTTP Protocol", curses.color_pair(12))
                                # Show first line
                                try:
                                    first_line = raw_data.split(b'\r\n')[0].decode('utf-8', errors='ignore')
                                    self.stdscr.addstr(row+3, 6, f"First line: {first_line[:width-12]}", curses.color_pair(7))
                                except:
                                    pass
                            # Check for other text protocols
                            elif b'text' in raw_data or b'xml' in raw_data:
                                self.stdscr.addstr(row+2, 4, "🔍 Detected: Text-based Protocol", curses.color_pair(12))
                            else:
                                self.stdscr.addstr(row+2, 4, "🔍 Binary Payload", curses.color_pair(7))
                else:
                    self.stdscr.addstr(row, 4, "📦 No Payload", curses.color_pair(7))
                    
            else:
                self.stdscr.addstr(6, 2, "❌ This packet does not contain TCP layer", curses.color_pair(4))
                
        except Exception as e:
            self.stdscr.addstr(6, 2, f"Error in TCP analysis: {e}", curses.color_pair(4))
    
    def draw_main_view(self):
        """Draw the main view based on current mode"""
        if self.view_mode == "list":
            self.draw_packet_list()
        elif self.view_mode == "detail":
            self.draw_packet_detail()
        elif self.view_mode == "hex":
            self.draw_hex_view()
        elif self.view_mode == "tcp_analysis":
            self.draw_tcp_analysis()
    
    def draw_footer(self):
        """Draw the footer with controls"""
        try:
            height, width = self.stdscr.getmaxyx()
            
            # 🎮 Control instructions based on view mode
            if self.view_mode == "list":
                controls = [
                    f"{self.animals['cat']} Q:Quit",
                    f"{self.animals['dog']} S:Stop/Start",
                    f"{self.animals['rabbit']} C:Clear",
                    f"{self.animals['mouse']} ↑/↓:Navigate",
                    f"{self.animals['bear']} PgUp/PgDn:Scroll",
                    f"{self.animals['owl']} Enter:Details",
                    f"{self.animals['lion']} H:Hex View",
                    f"{self.animals['tiger']} T:TCP Analysis"
                ]
            else:
                controls = [
                    f"{self.animals['cat']} Q:Quit",
                    f"{self.animals['dog']} ←:Back to List",
                    f"{self.animals['bear']} Tab:Next View",
                    f"{self.animals['panda']} H:Hex View",
                    f"{self.animals['tiger']} T:TCP Analysis"
                ]
            
            control_text = " | ".join(controls)
            if len(control_text) > width - 2:
                control_text = control_text[:width-5] + "..."
                
            self.stdscr.addstr(height - 2, 1, control_text, curses.color_pair(3))
            
            # 🐾 Status message
            with self.lock:
                if self.view_mode == "list":
                    status_msg = "🐾 Sniffing packets..." if self.is_running else "😴 Sniffing stopped"
                else:
                    status_msg = f"👁️ Viewing {self.view_mode.replace('_', ' ').title()}"
            self.stdscr.addstr(height - 1, 1, status_msg, curses.color_pair(1))
        except curses.error:
            pass
    
    def update_display(self):
        """Update the entire display"""
        try:
            self.stdscr.clear()
            self.draw_header()
            self.draw_main_view()
            self.draw_footer()
            self.stdscr.refresh()
        except curses.error:
            pass
    
    def packet_handler(self, packet):
        """Handle captured packets"""
        if not self.is_running:
            return
            
        # 📦 Extract packet information
        packet_info = {
            'no': 0,
            'time': datetime.now().strftime('%H:%M:%S.%f')[:-3],
            'src': 'Unknown',
            'dst': 'Unknown',
            'proto': 'Unknown',
            'len': len(packet),
            'info': '',
            'raw_packet': packet  # Store raw packet for deep analysis
        }
        
        # 🔍 Parse packet details
        if IP in packet:
            packet_info['src'] = packet[IP].src
            packet_info['dst'] = packet[IP].dst
            
            if TCP in packet:
                packet_info['proto'] = 'TCP'
                packet_info['info'] = f"{packet[TCP].sport} → {packet[TCP].dport}"
                
                # 🌐 Check for common protocols
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    packet_info['info'] += " [HTTP]"
                elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                    packet_info['info'] += " [HTTPS]"
                elif packet[TCP].dport == 53 or packet[TCP].sport == 53:
                    packet_info['info'] += " [DNS]"
                    
                # 🚩 Common TCP flags
                flags = packet[TCP].flags
                flag_info = []
                if flags & 0x02: flag_info.append('SYN')
                if flags & 0x10: flag_info.append('ACK')
                if flags & 0x01: flag_info.append('FIN')
                if flags & 0x04: flag_info.append('RST')
                if flag_info:
                    packet_info['info'] += f" [{'|'.join(flag_info)}]"
                    
            elif UDP in packet:
                packet_info['proto'] = 'UDP'
                packet_info['info'] = f"{packet[UDP].sport} → {packet[UDP].dport}"
                
                # 🔍 Check for DNS
                if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                    packet_info['info'] += " [DNS]"
                    
            elif ICMP in packet:
                packet_info['proto'] = 'ICMP'
                packet_info['info'] = f"Type {packet[ICMP].type}, Code {packet[ICMP].code}"
                
        elif ARP in packet:
            packet_info['proto'] = 'ARP'
            packet_info['src'] = packet[ARP].psrc
            packet_info['dst'] = packet[ARP].pdst
            packet_info['info'] = f"ARP {packet[ARP].op}"
        
        # 📦 Add to packet list with thread safety
        with self.lock:
            self.stats['total'] += 1
            
            # Update protocol stats
            proto = packet_info['proto']
            if proto == 'TCP':
                self.stats['tcp'] += 1
                if '[HTTP]' in packet_info['info']:
                    self.stats['http'] += 1
                elif '[HTTPS]' in packet_info['info']:
                    self.stats['https'] += 1
                elif '[DNS]' in packet_info['info']:
                    self.stats['dns'] += 1
            elif proto == 'UDP':
                self.stats['udp'] += 1
                if '[DNS]' in packet_info['info']:
                    self.stats['dns'] += 1
            elif proto == 'ICMP':
                self.stats['icmp'] += 1
            elif proto == 'ARP':
                self.stats['arp'] += 1
            
            packet_info['no'] = self.stats['total']
            self.packets.append(packet_info)
    
    def start_sniffing(self):
        """Start packet sniffing"""
        if self.is_running:
            return
            
        self.is_running = True
        
        def sniff_thread():
            try:
                sniff(iface=self.interface,
                      prn=self.packet_handler,
                      lfilter=lambda x: self.is_running,
                      filter=self.filter_exp if self.filter_exp else None,
                      count=0)
            except Exception:
                with self.lock:
                    self.is_running = False
        
        self.sniff_thread = threading.Thread(target=sniff_thread, daemon=True)
        self.sniff_thread.start()
    
    def stop_sniffing(self):
        """Stop packet sniffing gracefully"""
        self.is_running = False
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.sniff_thread.join(timeout=1.0)
    
    def clear_packets(self):
        """Clear all captured packets"""
        with self.lock:
            self.packets.clear()
            self.selected_row = 0
            self.scroll_offset = 0
            self.detail_packet_idx = -1
            self.view_mode = "list"
            # Reset stats except total
            for key in self.stats:
                if key != 'total':
                    self.stats[key] = 0
    
    def scroll_up(self, lines=1):
        """Scroll up by specified lines"""
        with self.lock:
            packets_count = len(self.packets)
            if packets_count == 0:
                return
                
            self.scroll_offset = max(0, self.scroll_offset - lines)
            self.selected_row = max(0, min(self.selected_row, packets_count - 1))
    
    def scroll_down(self, lines=1):
        """Scroll down by specified lines"""
        with self.lock:
            packets_count = len(self.packets)
            if packets_count == 0:
                return
                
            max_scroll = max(0, packets_count - self.visible_rows)
            self.scroll_offset = min(max_scroll, self.scroll_offset + lines)
            self.selected_row = max(0, min(self.selected_row, packets_count - 1))
    
    def move_selection(self, direction):
        """Move selection up or down"""
        with self.lock:
            packets_count = len(self.packets)
            if packets_count == 0:
                return
                
            self.selected_row = max(0, min(self.selected_row + direction, packets_count - 1))
            
            # Auto-scroll to keep selection visible
            if self.selected_row < self.scroll_offset:
                self.scroll_offset = self.selected_row
            elif self.selected_row >= self.scroll_offset + self.visible_rows:
                self.scroll_offset = self.selected_row - self.visible_rows + 1
    
    def enter_detail_view(self):
        """Enter detail view for selected packet"""
        with self.lock:
            if self.packets:
                self.detail_packet_idx = self.selected_row
                self.view_mode = "detail"
    
    def cycle_view_mode(self):
        """Cycle through different view modes"""
        if self.view_mode == "detail":
            self.view_mode = "hex"
        elif self.view_mode == "hex":
            self.view_mode = "tcp_analysis"
        elif self.view_mode == "tcp_analysis":
            self.view_mode = "detail"
        else:
            self.view_mode = "detail"
    
    def run(self):
        """Main application loop"""
        self.stdscr.nodelay(True)
        self.stdscr.keypad(True)
        
        # 🚀 Start sniffing automatically
        self.start_sniffing()
        
        while True:
            current_time = time.time()
            
            # 🎨 Update display at controlled intervals
            if current_time - self.last_update > self.update_interval:
                self.update_display()
                self.last_update = current_time
            
            # 🎮 Handle user input
            try:
                key = self.stdscr.getch()
                if key == ord('q') or key == ord('Q'):
                    break
                elif key == ord('s') or key == ord('S'):
                    if self.is_running:
                        self.stop_sniffing()
                    else:
                        self.start_sniffing()
                elif key == ord('c') or key == ord('C'):
                    self.clear_packets()
                elif key == curses.KEY_UP:
                    if self.view_mode == "list":
                        self.move_selection(-1)
                elif key == curses.KEY_DOWN:
                    if self.view_mode == "list":
                        self.move_selection(1)
                elif key == curses.KEY_PPAGE:  # Page Up
                    if self.view_mode == "list":
                        self.scroll_up(self.visible_rows - 1)
                elif key == curses.KEY_NPAGE:  # Page Down
                    if self.view_mode == "list":
                        self.scroll_down(self.visible_rows - 1)
                elif key == curses.KEY_HOME:
                    if self.view_mode == "list":
                        with self.lock:
                            self.selected_row = 0
                            self.scroll_offset = 0
                elif key == curses.KEY_END:
                    if self.view_mode == "list":
                        with self.lock:
                            if self.packets:
                                self.selected_row = len(self.packets) - 1
                                if len(self.packets) > self.visible_rows:
                                    self.scroll_offset = len(self.packets) - self.visible_rows
                elif key == curses.KEY_ENTER or key == 10 or key == 13:
                    if self.view_mode == "list":
                        self.enter_detail_view()
                elif key == 27:  # ESC key
                    if self.view_mode != "list":
                        self.view_mode = "list"
                elif key == curses.KEY_BACKSPACE or key == 127 or key == 263:  # Backspace
                    if self.view_mode != "list":
                        self.view_mode = "list"
                elif key == ord('h') or key == ord('H'):
                    with self.lock:
                        if self.packets and self.view_mode == "list":
                            self.detail_packet_idx = self.selected_row
                        if self.view_mode != "list":
                            self.view_mode = "hex"
                        else:
                            self.view_mode = "hex"
                            self.detail_packet_idx = self.selected_row
                elif key == ord('t') or key == ord('T'):
                    with self.lock:
                        if self.packets and self.view_mode == "list":
                            self.detail_packet_idx = self.selected_row
                        if self.view_mode != "list":
                            self.view_mode = "tcp_analysis"
                        else:
                            self.view_mode = "tcp_analysis"
                            self.detail_packet_idx = self.selected_row
                elif key == ord('\t'):  # Tab key
                    if self.view_mode != "list":
                        self.cycle_view_mode()
                elif key == curses.KEY_RESIZE:
                    # Handle terminal resize
                    self.stdscr.clear()
            except Exception:
                pass
            
            # ⏱️ Small delay to reduce CPU usage
            time.sleep(0.01)

def main(stdscr):
    # 🐍 Create and run the sniffer
    sniffer = TerminalPacketSniffer(stdscr)
    
    # 🎯 Parse command line arguments
    parser = argparse.ArgumentParser(description='🐍 Terminal Packet Sniffer')
    parser.add_argument('-i', '--interface', help='Network interface to sniff')
    parser.add_argument('-f', '--filter', help='BPF filter expression')
    parser.add_argument('-c', '--count', type=int, default=1000, help='Maximum packets to keep')
    
    args = parser.parse_args()
    
    # 🛠️ Apply arguments
    if args.interface:
        sniffer.interface = args.interface
    if args.filter:
        sniffer.filter_exp = args.filter
    if args.count:
        sniffer.packets = deque(maxlen=args.count)
    
    # 🚀 Run the application
    sniffer.run()

if __name__ == "__main__":
    # 🐍 Check for root privileges
    if os.geteuid() != 0:
        print("🚨 This script requires root privileges!")
        print("🔧 Please run with sudo:")
        print("   sudo python3 terminal_sniffer.py")
        sys.exit(1)
    
    # 🎨 Run with curses wrapper
    try:
        wrapper(main)
    except KeyboardInterrupt:
        print(f"\n{TerminalPacketSniffer({}).animals['snake']} Sniffer interrupted by user")
    except Exception as e:
        print(f"\n{TerminalPacketSniffer({}).animals['wolf']} Unexpected error: {e}")
    finally:
        curses.endwin()
