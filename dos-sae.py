#!/usr/bin/python
from scapy.all import *

import sys, select
import signal
import os
import string
import random
import threading
import subprocess
from datetime import datetime
import hashlib
from binascii import unhexlify
sys.path.append('src/')
import saee
import graphs
import json




#conf.use_pcap = True

	


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    STH = '\33[100m'
    STH1 = '\33[104m'
    STH2 = '\33[5m'


		
def signal_Handler(signum, frame):
	
	if signum == signal.SIGUSR2:
		global toStop
		while toStop == 1:
			pass
		print("\n\n"+bcolors.OKBLUE +"STA is online"+bcolors.ENDC+"\n....Resuming execution....")
		time.sleep(1)
	else:
		pass
signal.signal(signal.SIGUSR2, signal_Handler)		
		
		




	
global deauth_to_Send_stop
deauth_to_Send_stop = 0
class deauth_Monitor(threading.Thread):
	def run(self):
		
		print("Started deauth monitoring!")
		sniff(iface = infos.ATTACKING_INTERFACE, store=0,stop_filter = self.stopfilter, filter = "(ether dst " + infos.STA_MAC + " and ether src " + infos.AP_MAC + ") or (ether dst " + infos.AP_MAC + " and ether src " + infos.STA_MAC + ")")
		
		
	def stopfilter(self,packet):
		global deauth_to_Send_stop
		global stop_ALL_threads
		keyword = "Deauthentification"
		if stop_ALL_threads == 1:
			return True
		if packet.haslayer(Dot11Deauth) or keyword in packet.summary():
		
                        print(bcolors.FAIL + "\nFound Deauthentication frame" + bcolors.ENDC)
                        time_Found = datetime.now().strftime("%H:%M:%S")	
                        subprocess.call(['echo '+ str(time_Found) + '. Found deauth from ' + str(packet[Dot11].addr2) + ' to ' + str(packet[Dot11].addr1) +' >> ' + deauth_Path + ' during: ' + state.message], shell = True)
                        deauth_to_Send_stop = 1

                        return False
		elif packet.haslayer(Dot11Disas):
                        print(bcolors.FAIL + "\nFound Disassociation frame" + bcolors.ENDC)
                        time_Found = datetime.now().strftime("%H:%M:%S")
                        subprocess.call(['echo '+ str(time_Found) + '. Found disas from ' + str(packet[Dot11].addr2) + ' to ' + str(packet[Dot11].addr1) +' >> ' + deauth_Path + ' during: ' + state.message], shell = True)
                        deauth_to_Send_stop = 1
                        return False
		else:
			return False

 
	 
class Generate_Frames:

	def __init__(self, AP_MAC, AP_CHANNEL, AP_MAC_DIFFERENT, CHANNEL_DIFFERENT, STA_MAC, ATTACKING_INTERFACE, MONITORING_INTERFACE, PASSWORD):
	
		self.AP_MAC = AP_MAC
		self.AP_CHANNEL = AP_CHANNEL
		self.AP_MAC_DIFFERENT = AP_MAC_DIFFERENT
		self.CHANNEL_DIFFERENT = CHANNEL_DIFFERENT
		self.STA_MAC = STA_MAC
		self.ATTACKING_INTERFACE = ATTACKING_INTERFACE
		self.MONITORING_INTERFACE = MONITORING_INTERFACE
		self.PASSWORD = PASSWORD
		

	
	def generate_Authbody(self, auth_Algorithm, sequence_Number, status1):

		auth_Body = RadioTap()/Dot11(type=0, subtype=11, addr1=self.AP_MAC, addr2=self.STA_MAC, addr3=self.AP_MAC)/Dot11Auth(algo = auth_Algorithm, seqnum=sequence_Number, status = status1)
		return auth_Body

	def generate_valid_Commit_Authbody(self):
		auth_Body = self.generate_Authbody(3,1,0)
		return auth_Body
		
	def generate_valid_Confirm_Authbody(self):
		auth_Body = self.generate_Authbody(3,2,0)
		return auth_Body
	
	def generate_Group(self):
		group = '\x13\x00'
		return group
	def generate_send_Confirm(self, valid):
  		if valid == 0:
  			send = '\x00\x00'
  		if valid == 1:
  			send = '\x00\x02'			
  		return send
	def generate_payload_Confirm(self):
  		confirm = 'something'
  		return confirm
  	
	def generate_Custom_Commit(self,auth, seq, stat):
  		body = self.generate_Authbody(auth, seq, stat)
  		group = self.generate_Group()
  		print(infos.STA_MAC.upper() +  infos.AP_MAC.upper())
  		scalar , finite = saee.generate_Scalar_Finite(infos.PASSWORD,infos.STA_MAC.upper(),infos.AP_MAC.upper())
  		frame = body/group/scalar/finite
  		return frame
  	
	def generate_Custom_Confirm(self,auth ,seq, stat, valid):
  		body = self.generate_Authbody(auth, seq, stat)
  		send = self.generate_send_Confirm(valid)
  		confirm = self.generate_payload_Confirm()
  		frame = body/send/confirm
  		return frame
  		
	def generate_correct_Commit(self):
  		auth_Body = self.generate_valid_Commit_Authbody()
  		group = self.generate_Group()
  		scalar, finite = saee.generate_Scalar_Finite(infos.PASSWORD,infos.STA_MAC,infos.AP_MAC)
  		frame = auth_Body/group/scalar/finite
  		return frame
  		
  		
	def send_Frame(self,frame, burst_Number):
		
		
		sendp(frame,count = burst_Number, iface=self.ATTACKING_INTERFACE, verbose = 0)
		
	
	def change_to_diff_Frequency(self):
		
		temp_Mac = self.AP_MAC
		self.AP_MAC = self.AP_MAC_DIFFERENT
		self.AP_MAC_DIFFERENT = temp_Mac
		
		temp_Channel = self.AP_CHANNEL
		self.AP_CHANNEL = self.CHANNEL_DIFFERENT
		self.CHANNEL_DIFFERENT = temp_Channel
	
		
		subprocess.call(['iwconfig ' + self.ATTACKING_INTERFACE + ' channel ' + self.AP_CHANNEL], shell = True)
		current_Channel = subprocess.check_output(['iw '+ self.ATTACKING_INTERFACE+' info | grep channel | cut -d " " -f2'], shell = True)
		
		print('\nAP_MAC changed to: ' + self.AP_MAC + '\nChannel changed to: ' + current_Channel)

			
	def toString(self):
		print('AP_MAC: ' + self.AP_MAC)
		print('AP_CHANNEL: ' + self.AP_CHANNEL)
		print('AP_MAC_DIFFERENT: ' + self.AP_MAC_DIFFERENT)
		print('CHANNEL_DIFFERENT: ' + self.CHANNEL_DIFFERENT)
		print('STA_MAC: ' + self.STA_MAC)
		print('ATTACKING_INTERFACE: ' + self.ATTACKING_INTERFACE)
		print('MONITORING_INTERFACE: ' + self.MONITORING_INTERFACE)


class save_State:
	def __init__(self):
	
		self.order_Values = []
		self.dc_values = []
		self.frames_to_Send = 1
		self.auth_values_to_Try = 0
		self.sequence_values_to_Try = 1
		self.status_values_to_Try = 0
		self.identifier = 0
		self.message = 'sth'
	
	def setValues(self,frames_to_Send,auth_values_to_Try,sequence_values_to_Try,status_values_to_Try,identifier):
		self.frames_to_Send = frames_to_Send
		self.auth_values_to_Try = auth_values_to_Try
		self.sequence_values_to_Try = sequence_values_to_Try
		self.status_values_to_Try = status_values_to_Try
		self.identifier = identifier
	
	def __eq__(self,other):
		return self.message == other.message
		
	def append_Order(self,listt):
		found = 0
		if not self.order_Values:
			self.order_Values.append(listt)
		else:
			for a in self.order_Values:
				if a[0] == listt[0] and a[1] == listt[1] and a[2] == listt[2]:
					found = 1
			if found == 0:
				self.order_Values.append(listt)
			
	
	def append_Dc(self,listt):
		found = 0
		if not self.dc_values:
			self.dc_values.append(listt)
		else:
			for a in self.dc_values:
				if a[0] == listt[0] and a[1] == listt[1] and a[2] == listt[2]:
					found = 1
					break
			if found == 0:
				self.dc_values.append(listt)
			
				


class fuzz:

	def __init__(self):
		self.total_frames_to_Send = 50
		
		self.auth_values_to_Try = [0, 1,  2, 3, 200]
		self.sequence_values_to_Try = [1, 2, 3, 4, 200]
		self.status_values_to_Try = [0, 1, 200]
		
		
	def construct_and_Send(self, identifier, burst_Number):
		global stopThread 
		time.sleep(0.01)
		
		for auth_value in self.auth_values_to_Try:
			for sequence_value in self.sequence_values_to_Try:
				for status_value in self.status_values_to_Try:
				
					state.setValues(self.total_frames_to_Send,auth_value,sequence_value,status_value,identifier)
					
					self.sendd(auth_value,sequence_value,status_value,identifier,burst_Number)
					
							
						
	def construct_and_Send2(self,identifier):
	
		time.sleep(10)
		for a in state.order_Values:
						
			auth_valuee = a[0]
			state.auth_values_to_Try = auth_valuee
			
			
			sequence_valuee = a[1]
			state.sequence_values_to_Try = sequence_valuee
			
			status_value = a[2]
			state.status_values_to_Try = status_value
			
			
			
			self.sendd(auth_valuee,sequence_valuee,status_value,identifier,128)

						
		
		
	def fuzz_Empty_Bodies(self,burst_Number):
		self.construct_and_Send(1,burst_Number)
		
	def fuzz_validCommit_EmptyBodies(self,burst_Number):
		self.construct_and_Send(2,burst_Number)
	
	def fuzz_validCommit_goodConfirm(self,burst_Number):
		self.construct_and_Send(3,burst_Number)
		
	def fuzz_validCommit_badConfirm(self,burst_Number):
		self.construct_and_Send(4,burst_Number)
		
	def fuzz_Commit(self,burst_Number):
		self.construct_and_Send(5,burst_Number)
			
	def fuzz_goodConfirm(self,burst_Number):
		self.construct_and_Send(6,burst_Number)
	def fuzz_badConfirm(self,burst_Number):
		self.construct_and_Send(7,burst_Number)
		
		
		
	def cyrcle1(self):
		
		self.fuzz_Empty_Bodies(1)
		self.fuzz_validCommit_EmptyBodies(1)
		self.fuzz_validCommit_goodConfirm(1)
		self.fuzz_validCommit_badConfirm(1)
		self.fuzz_Commit(1)
		self.fuzz_goodConfirm(1)
		self.fuzz_badConfirm(1)
		
	def cyrcle2(self):
		time.sleep(1)
		self.cyrcle1()
	
	def cyrcle3(self):
	

		time.sleep(1)
		self.construct_and_Send2(1)
		self.construct_and_Send2(2)
		self.construct_and_Send2(3)
		self.construct_and_Send2(4)
		self.construct_and_Send2(5)
		self.construct_and_Send2(6)
		self.construct_and_Send2(7)
		
		time.sleep(1)
		
	def cyrcle4(self):
		self.cyrcle3()
		

		
	def initiate_Fuzzing_LOGICAL_MODE(self):
		self.cyrcle1()
		if CHANNEL_DIFFERENT_FREQUENCY != '00':
			infos.change_to_diff_Frequency()
			self.cyrcle2()
			infos.change_to_diff_Frequency()
			
		self.cyrcle3()
		
		if CHANNEL_DIFFERENT_FREQUENCY != '00':
			infos.change_to_diff_Frequency()
			self.cyrcle4()
			infos.change_to_diff_Frequency()

		
	def initiate_Fuzzing_EXTENSIVE_MODE(self):
		self.auth_values_to_Try = list(range(0, 65534))
		self.sequence_values_to_Try = list(range(0, 65534))
		self.status_values_to_Try = list(range(0, 65534))
		self.initiate_Fuzzing_LOGICAL_MODE()
		
		
		
	def sendd(self,auth_value,sequence_value,status_value,identifier,burst_Number):
		global stopThread
		global deauth_to_Send_stop
		deauth_to_Send_stop = 0
		toprint = 1
		stopThread = 0
		firs=1
		self.total_frames_to_Send = 50

		
		for times in range (0, self.total_frames_to_Send):
		
		
			if identifier == 1:
				if firs == 1:
					frame = infos.generate_Authbody(auth_value, sequence_value, status_value)
					firs = 0
				message =  " eempty body frames with values : "

				infos.send_Frame(frame, burst_Number)
			elif identifier == 2:
				if firs == 1:
					self.total_frames_to_Send = 25
					frame = infos.generate_Custom_Commit(3, 1, 0)
					frame2 = infos.generate_Authbody(auth_value, sequence_value, status_value)
					firs = 0
				message =  " valid commits folowed by empty body frames with values: "
				infos.send_Frame(frame,burst_Number)
				time.sleep(0.05)
				infos.send_Frame(frame2,burst_Number)
			elif identifier == 3:
				if firs == 1:
					self.total_frames_to_Send = 25
					frame = infos.generate_Custom_Commit(3, 1, 0)
					frame2 = infos.generate_Custom_Confirm(auth_value, sequence_value, status_value, 0)
					firs = 0
				message =  " valid commits folowed by confirm with send-confirm value = 0 ,, with body values : "
				infos.send_Frame(frame,burst_Number)
				time.sleep(0.05)
				infos.send_Frame(frame2,burst_Number)
			elif identifier == 4:
				if firs == 1:
					self.total_frames_to_Send = 25
					frame = infos.generate_Custom_Commit(3, 1, 0)
					frame2 = infos.generate_Custom_Confirm(auth_value, sequence_value, status_value, 1)
					firs = 0
				message =  " valid commits folowed by confirm with send-confirm value = 2 ,, with body values : "
				infos.send_Frame(frame,burst_Number)
				time.sleep(0.05)
				infos.send_Frame(frame2,burst_Number)
				
			elif identifier == 5:
				if firs == 1:
					frame = infos.generate_Custom_Commit(auth_value, sequence_value, status_value)
					firs = 0
				message =  " commits with body values : "
				infos.send_Frame(frame,burst_Number)

			elif identifier == 6:
				if firs == 1:
					firs = 0
					frame = infos.generate_Custom_Confirm(auth_value, sequence_value, status_value, 0)
				message =  " confirms with send-confirm value = 0 ,, with body values : "
				infos.send_Frame(frame,burst_Number)
							
										
			elif identifier == 7:
				if firs == 1:
					firs = 0
					frame = infos.generate_Custom_Confirm(auth_value, sequence_value, status_value, 1)
				message =  " confirms with send-confirm value = 2 ,, with body values : "
				infos.send_Frame(frame,burst_Number)


			

										
			if toprint == 1:
				self.logging(auth_value, sequence_value, status_value, message,burst_Number)
				toprint = 0
				print('\n')
		time.sleep(4)
		stopThread = 1
		if MONITORING_INTERFACE == '00':
			if deauth_to_Send_stop == 1:
				print("\nFound deauthentication frames during the specific attack. Pausing 60 sec before continuing to the next case.")
				time.sleep(60)
				deauth_to_Send_stop = 0
		time.sleep(4)
								
		
	
	def logging(self,auth,seq,stat,message,burst_number):
	
		string = ("Sending " + str(self.total_frames_to_Send) + message + str(auth) + " " + str(seq) + " " + str(stat) )
		if int(infos.AP_CHANNEL) > 15:
			string = string + ' ...  5G'
		if burst_number > 1:
			string = string + '... BURSTY'
		
		print('\n' + string)
		state.message = string
	
				 
	
		
		
class nonresponsiveness_Monitor(threading.Thread):
					
				
	def run(self):
		global stop_ALL_threads
		ip_prefix = self.find_my_Ip()
		sta_Ip = self.find_sta_Ip(ip_prefix)
		global start
		global toStop
		global stopThread 
		stopThread = 1
		toStop = 0
		first = 0
		counter = 0
		while True:
			if stop_ALL_threads==1:
				break
			if stopThread == 0:
				ping_Response = self.pingg(sta_Ip)
				
				if ping_Response == 'notfound':
					
					if first == 0 :
						first = 1
						startT = time.time()
						
						new_List = list()
						new_List.append(state.auth_values_to_Try)
						new_List.append(state.sequence_values_to_Try)
						new_List.append(state.status_values_to_Try)
					
						state.append_Order(new_List)
						

		
					print("Pinging STOPED responding")
			
						
				else:
					if first == 1:
						first = 0
						endT = time.time()
						time_Unresponsive = (endT - startT)
						time_Found = datetime.now().strftime("%H:%M:%S")	
						subprocess.call(['echo '+ str(time_Found) + '. Came back online after  ' + str(time_Unresponsive) + ' of unresponsivness   During: ' + state.message + ' >> ' + nonresponsive_Path], shell = True)
					start = 1
					print("Pinging is responding")
				
				time.sleep(0.5)	
			else:
				toStop = 1
			
				print("Stoping execution until checks")
				os.kill(os.getpid(),signal.SIGUSR2)
				
				
				
				if first == 1:
					ping_Response = self.pingg(sta_Ip)
					
					fir = 1
					pi = 1
					while ping_Response == "notfound" or ping_Response == '1':
						
						print("Pinging STOPED responding")
						if fir == 1:
							star = time.time()
							fir = 0
						en = time.time()
						if en - star > 20:
							print("calling MTI")
							sta_Ip = self.find_sta_Ip(ip_prefix)
					
							
						ping_Response = self.pingg(sta_Ip)
						
					first = 0
					endT = time.time()
					time_Unresponsive = (endT - startT)
					time_Found = datetime.now().strftime("%H:%M:%S")	
					subprocess.call(['echo '+ str(time_Found) + '. Came back online after  ' + str(time_Unresponsive) + ' of unresponsivness   During: ' + state.message + ' >> ' + nonresponsive_Path], shell = True)
				time.sleep(1)
				toStop = 0	
				start = 1
				stopThread = 0

						
	def pingg(self,sta_Ip):
		try:
			sa = subprocess.check_output(['ping -f -c 1 -W 1 ' + sta_Ip + ' -I ' + MONITORING_INTERFACE + ' > /dev/null && echo found || echo notfound'], shell = True)
			sa = sa[:-1]
			return sa
		except Exception as e :
			logger.exception(str(e))
			return '1'
				
		
				
	def find_my_Ip(self):
		while True:
			print("\n\n" + bcolors.OKGREEN + "----Retrieving your ip address----" + bcolors.ENDC)
			ip_prefix = subprocess.check_output(['hostname -I | cut -d "." -f 1,2,3 '], shell = True)
			ip_prefix = ip_prefix[:-1]
			if len(ip_prefix) > 5:
				print("Found ip prefix: "+ ip_prefix + ' ')
				
				return ip_prefix
			else:
				print("Could not retrieve your ip address! Retrying in 3 seconds.")
				time.sleep(3)
				
			

			
	def find_sta_Ip(self,ip_prefix):
		temp=ip_prefix
		print("\n\n"+bcolors.OKGREEN+"----Pinging all hosts with an ip prefix of: " + ip_prefix + '.xx ----'+bcolors.ENDC)
		found = 0
		fe = 1
		while found == 0:
			time.sleep(0.5)
			for i in range(1,254):
				ip_prefix+='.' + str(i)
				try:
					subprocess.call(['ping -f -c 1 -W 0.01 ' + ip_prefix + ' -I ' + MONITORING_INTERFACE + ' > /dev/null '], shell = True)
				except:
					print("Catched. Most likely your NIC stoped working!")	
				
				ip_prefix = temp
			
			try:	
				sta_Ip = subprocess.check_output(['arp -a | grep '+infos.STA_MAC.lower()+' | tr -d "()" | cut -d " " -f2'], shell = True)
				sta_Ip = sta_Ip[:-1]

			except Exception as e :
				print("arp -a exception.")
				sta_Ip = '1'
				
			if len(sta_Ip) > 5:
				print("RETRIEVED IP OF MAC: " + TARGETED_STA_MAC_ADDRESS + "   is   " + sta_Ip + "\n" )
				found = 1
				responsive = self.pingg(sta_Ip)
				while responsive == 'notfound' or responsive == '1':
					if responsive == '1':
						print("Sleeping 10s because something went really wrong.Check your nic")
						time.sleep(10)
					else:
						print("Pinging STOPED responding")
					responsive = self.pingg(sta_Ip)
				
				print("is responsive")
				return sta_Ip
			else: 
				print("COULD NOT FIND IP OF MAC: " + TARGETED_STA_MAC_ADDRESS + "... Retrying in 1 second!!")
				
				if state.message != 'sth':
			  	       
			  	       
					if fe == 1:				
						fe = 0
						print("Disconnected")

						new_List = list()
						new_List.append(state.auth_values_to_Try)
						new_List.append(state.sequence_values_to_Try)
						new_List.append(state.status_values_to_Try)
									
						state.append_Dc(new_List)
						
						subprocess.call(['echo DISCONNECTED >> ' + nonresponsive_Path], shell = True)
					
				time.sleep(0.5)
				
class neccessary_Tests():

	def __init__(self):
		self.check_monitor_mode()
		self.check_channel()
		self.search_AP()
		self.check_sae_Exchange()
		time.sleep(3)
	
	
	def thread_function(self):
		time.sleep(0.1)
	
		frame = infos.generate_Custom_Confirm(3,2,0,0)
		print("Sending  CONFIRM")
		sendp(frame,iface=infos.ATTACKING_INTERFACE, verbose = 0)
	    
	    
	def check_sae_Exchange(self):
	
		print(bcolors.OKGREEN + "\n\nPerforming a SAE exchange: "+  bcolors.ENDC )
		frame = infos.generate_Custom_Commit(3,1,0)
		for i in range (1,6):
			x = threading.Thread(target=self.thread_function)
			x.start()

			print("Sending  COMMIT")
			answer = srp1(frame, timeout = 3, iface = infos.ATTACKING_INTERFACE, inter = 0.1,verbose = 0)
			if answer:
				print("Exchange performed successfully  on "+str(i) + " try\n")
				break
			else:
				print(bcolors.FAIL + "Didnt get answer. "+bcolors.ENDC+" Retrying for "+str(i)+ " time. Max tries: 5\n" )
				
	
	def check_monitor_mode(self):
		mode = 's'
		
		print(bcolors.OKGREEN + "Validating if mode of attacking interface: "+  bcolors.ENDC +  bcolors.OKBLUE + infos.ATTACKING_INTERFACE + bcolors.ENDC +  bcolors.OKGREEN +" is set to: " + bcolors.ENDC + bcolors.OKBLUE +"-- MONITOR MODE --" + bcolors.ENDC)
		try:
			mode = subprocess.check_output(['iwconfig '+ infos.ATTACKING_INTERFACE+' | grep Monitor '], shell = True)
		except subprocess.CalledProcessError as e:
			mode = '1'
		if (len(mode) > 5):
			print(infos.ATTACKING_INTERFACE + " IS set to monitor mode. \n\n")
		else:
			print(infos.ATTACKING_INTERFACE + " IS NOT set to monitor mode.")
			print("TERMINATING...")
			sys.exit(0)
			
		
		
		
	def check_channel(self):
		foundd = 0
		print(bcolors.OKGREEN + "Validating if channel of: "+  bcolors.ENDC +  bcolors.OKBLUE + infos.ATTACKING_INTERFACE + bcolors.ENDC +  bcolors.OKGREEN +" is set to: " + bcolors.ENDC + bcolors.OKBLUE +"-- "+ infos.AP_CHANNEL + " --"+ bcolors.ENDC)
		try:
			channel = subprocess.check_output(['iw '+ infos.ATTACKING_INTERFACE+' info | grep channel | cut -d " " -f2'], shell = True)
		except subprocess.CalledProcessError as e:
			print("iw interface info | grep channel | cut -d " " -f2 returned error")
			channel = '0'
		channel = channel[:-1]
		while True:
			if channel == infos.AP_CHANNEL:
				print("Channel of " + infos.ATTACKING_INTERFACE + " IS set to: " +infos.AP_CHANNEL+'\n\n')
				break;
			else:
				print("Channel of " + infos.ATTACKING_INTERFACE + " IS NOT set to: " +infos.AP_CHANNEL + " OR  i cannot correctly retrieve the channel information\n")
				print("You are suggested to manually check and set the interface to the correct channel (if needed)")
				print("If you are sure that the channel is set correctly, INGORE this message.\n\n")
				break;
				
			

	def search_AP(self):
		
		print(bcolors.OKGREEN + "Searching for AP in range, with mac address: " + bcolors.ENDC + bcolors.OKBLUE +"--- "+ infos.AP_MAC + " ---"+ bcolors.ENDC)
		print("Searching...")
		sniff(iface = infos.ATTACKING_INTERFACE, stop_filter = self.stopfilter, store = 0)
		
		
		
	def stopfilter(self,pkt):
		if pkt.haslayer(Dot11):
			dot11_layer = pkt.getlayer(Dot11)
			
			if isinstance(dot11_layer.addr2, str):
				if dot11_layer.addr2.lower() == infos.AP_MAC.lower():
					print("\nAP found")
					return True
			
		

#----------------------#	

os.system('cat src/logo.txt')

config = json.load(open('src/config.json', 'r'))

AP_MAC_ADDRESS = config["AP_info"]["AP_MAC_ADDRESS"]
AP_CHANNEL = config["AP_info"]["AP_CHANNEL"]
AP_MAC_DIFFERENT_FREQUENCY = config["AP_info"]["AP_MAC_DIFFERENT_FREQUENCY"]
CHANNEL_DIFFERENT_FREQUENCY = config["AP_info"]["CHANNEL_DIFFERENT_FREQUENCY"]
TARGETED_STA_MAC_ADDRESS = config["STA_info"]["TARGETED_STA_MAC_ADDRESS"]
ATTACKING_INTERFACE = config["ATT_interface_info"]["ATTACKING_INTERFACE"]
MONITORING_INTERFACE = config["ATT_interface_info"]["MONITORING_INTERFACE"]
PASSWORD = config["AP_info"]["PASSWORD"]
    	


	
terminal_width = int(subprocess.check_output(['stty', 'size']).split()[1])
print("\n")
print('-'*terminal_width)
print((bcolors.OKGREEN + "INFORMATION RETRIEVED FROM CONFIG FILE" + bcolors.ENDC).center(terminal_width))
print(('  ' + bcolors.STH + 'AP_MAC:   ' + AP_MAC_ADDRESS + bcolors.ENDC).center(terminal_width))
print(('  ' + bcolors.STH + 'AP_CHANNEL:   ' + AP_CHANNEL + bcolors.ENDC).center(terminal_width))
print("\n")
print((bcolors.STH + 'AP_MAC_DIFFERENT_FREQUENCY:   ' + AP_MAC_DIFFERENT_FREQUENCY + bcolors.ENDC).center(terminal_width))
print(('  ' + bcolors.STH + 'CHANNEL_DIFFERENT_FREQUENCY:   ' + CHANNEL_DIFFERENT_FREQUENCY + bcolors.ENDC).center(terminal_width))
print("\n")
print(('  ' + bcolors.STH + 'TARGETED_STA_MAC_ADDRESS:   ' + TARGETED_STA_MAC_ADDRESS + bcolors.ENDC).center(terminal_width))
print("\n")
print(('  ' + bcolors.STH + 'ATTACKING INTERFACE:   ' + ATTACKING_INTERFACE + bcolors.ENDC).center(terminal_width))
print(('  ' + bcolors.STH + 'MONITORING INTERFACE:   ' + MONITORING_INTERFACE + bcolors.ENDC).center(terminal_width))
print("\n")
print(('  ' + bcolors.STH + 'PASSWORD:   ' + PASSWORD + bcolors.ENDC).center(terminal_width))
print('-'*terminal_width)

infos = Generate_Frames(AP_MAC_ADDRESS, AP_CHANNEL, AP_MAC_DIFFERENT_FREQUENCY ,CHANNEL_DIFFERENT_FREQUENCY, TARGETED_STA_MAC_ADDRESS, ATTACKING_INTERFACE, MONITORING_INTERFACE,PASSWORD)

folder_Name = datetime.now().strftime("fuzz%d-%m-%y__%H:%M:%S")
folder_Path = 'Logs/' + folder_Name
deauth_Path = folder_Path + '/Deauth.txt'
nonresponsive_Path = folder_Path + '/Nonresponsive.txt'

subprocess.call(['mkdir -m 777 -p Logs'], shell = True)
subprocess.call(['mkdir -m 777 ' + folder_Path], shell = True)
subprocess.call(['touch ' + deauth_Path + ' && chmod 777 ' + deauth_Path], shell = True)
subprocess.call(['touch ' + nonresponsive_Path + ' && chmod 777 ' + nonresponsive_Path], shell = True)


state = save_State()

fuzz = fuzz()

neccessary_Tests = neccessary_Tests()

global start
start =0	

if CHANNEL_DIFFERENT_FREQUENCY == '00':
	print("Skipping attack on the other frequency\n")
	



thread2 = deauth_Monitor()
thread2.start()
time.sleep(1)

if MONITORING_INTERFACE == '00':
	print("\nProcceding without NON-RESPONSIVNESS MONITORING!")
	start = 1
else:
	thread1 = nonresponsiveness_Monitor()
	thread1.start()



global stop_ALL_threads 
stop_ALL_threads=0

while True:




	if start == 1:
		fuzz.initiate_Fuzzing_LOGICAL_MODE()
		graphs.statisticss(nonresponsive_Path,state.order_Values)
		stop_ALL_threads = 1
				
		#fuzz.initiate_Fuzzing_EXTENDED_MODE()
		print("\n\nFUZZING FINISHED!")
		
		sys.exit(0)
		break
	

