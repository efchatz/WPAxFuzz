import subprocess




class graphss():
	
	def __init__(self,path):
		self.txt_Path = path
		self.Bursty_24g = ''
		self.noBursty_24g = ''
		self.Bursty_5g = ''
		self.noBursty_5g =''
		self.get_Instances()
		self.string_to_Search = []
		self.addString()
		
		
	def get_Instances(self):
	
		try:
			self.Bursty_24g = subprocess.check_output(['cat ' + self.txt_Path + ' | grep BURSTY | grep -v 5G'], shell = True)
		except Exception:
			self.Bursty_24g = ''
			
		try:	
			self.noBursty_24g = subprocess.check_output(['cat ' + self.txt_Path + ' | grep -v BURSTY | grep -v 5G | grep -v DISCONNECTED'], shell = True)
		except Exception:
			self.noBursty_24 = ''
			
			
		try:
			self.Bursty_5g = subprocess.check_output(['cat ' + self.txt_Path + ' | grep BURSTY | grep 5G '], shell = True, stderr=subprocess.STDOUT)
		except Exception:
			self.Bursty_5g = ''
			
		try:
			self.noBursty_5g = subprocess.check_output(['cat ' + self.txt_Path + ' | grep -v BURSTY | grep 5G | grep -v DISCONNECTED'], shell = True)
		except Exception:
			self.noBursty_5g = ''
			
			
	def average_per_Attackstr(self,name,string_of_Output):
	
		diferrent_Values = []

		
		
		if len(string_of_Output) > 3:

			alllines = string_of_Output.split('\n')
			
			print('\n\n'+ '-'*40 + name + '-'*40)
			for strings in self.string_to_Search:
				counter = 0
				average = 0
				for lines in alllines:
					if strings in lines:
						a = lines.split()[5]
						a=float("{:.2f}".format(float(a)))
						counter = counter + 1
						average = average + a

				if counter > 0 and average > 0:
					average=float("{:.2f}".format(float(average/counter)))
					diferrent_Values.append(average)
					print('['+ strings + ']:  Average not-responding time: ' + str(average) + 's || Instances:  ' + str(counter))
				
						
				#[int(s) for s in lines.split() if s.isdigit()]
			
		
	def average_per_Value(self,name, string_of_Output, listofLists):
		if len(string_of_Output) > 3:
			alllines = string_of_Output.split('\n')
			print('\n\n'+ '-'*40 + name + '-'*40)
			for listt in listofLists:
				counter = 0
				average = 0
				auth = listt[0]
				seq = listt[1]
				status= listt[2]
				
				for line in alllines:
					if (' '+str(auth) +' '+ str(seq) +' '+ str(status)) in line:
						a = line.split()[5]
						a=float("{:.2f}".format(float(a)))
						counter = counter + 1
						average = average + a
						
				if counter > 0 and average > 0:
					average=float("{:.2f}".format(float(average/counter)))
					
					print('For values ['+ str(auth) +' '+ str(seq) +' '+ str(status) + ']:  Average not-responding time: ' + str(average) + 's || Instances:  ' + str(counter))	
					
					
			
		
		
	def addString(self):
		self.string_to_Search.append('eempty body frames with values')
		self.string_to_Search.append('valid commits folowed by empty body frames with values')
		self.string_to_Search.append('valid commits folowed by confirm with send-confirm value = 0')
		self.string_to_Search.append('valid commits folowed by confirm with send-confirm value = 2')
		self.string_to_Search.append('commits with body values')
		self.string_to_Search.append('confirms with send-confirm value = 0')
		self.string_to_Search.append('confirms with send-confirm value = 2')
		
	
	
	def go(self,listofValues):
	
		self.average_per_Attackstr('2.4g',self.noBursty_24g)		
		self.average_per_Attackstr('2.4g Bursts',self.Bursty_24g)
		self.average_per_Attackstr('5g ',self.noBursty_5g)
		self.average_per_Attackstr('5g Bursts',self.Bursty_5g)
		
		self.average_per_Value('2.4g',self.noBursty_24g, listofValues)		
		self.average_per_Value('2.4g Bursts',self.Bursty_24g,listofValues)
		self.average_per_Value('5g ',self.noBursty_5g,listofValues)
		self.average_per_Value('5g Bursts',self.Bursty_5g,listofValues)
		
		
	

		
def statisticss(path,listofLists):
	graph = graphss(path)
	graph.go(listofLists)




