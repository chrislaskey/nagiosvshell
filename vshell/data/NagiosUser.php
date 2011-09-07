<?php //NagiosUser.php  nagios user class to handle authorized hosts, services, and admin functionality 




class NagiosUser
{	
	//boolean for users who can see and access all features 
	protected $admin = false; 
	//boolean for viewing all hosts and services 
	protected $sees_all = false; 

	//array for storing global authorizations from cgi file
	protected $authKeys = array(
		'authorized_for_all_host_commands' => false,
		'authorized_for_all_hosts' => false,
		'authorized_for_all_service_commands' => false,
		'authorized_for_all_services' => false,
		'authorized_for_configuration_information' => false,
		'authorized_for_system_commands' => false,
		'authorized_for_system_information' => false,
		'authorized_for_read_only' => true,	
		);
	
	protected $authHosts = array(); 
	//protected $authServices = array(); 
	protected $username; 
		
	//constructor 
	//initialize authorized hosts and services only upon construction and then cache data 
	//TODO move towards session auth so this info gets updated upon login and restart of Nagios 
	
	function __construct($username=false) {
		//some users have requested to turn off authentication or user other methods, this allows override and backwards compatibility 
		if(!$username)
			$this->username = $this->get_user(); 
		else $this->username = $username; //for users that hard-code a username: NOT RECOMMENDED  
		
		//build main authKeys array 
		$this->set_perms(); 
		
		$this->admin = $this->determine_admin(); 

		//if user level account, determin authorized objects 
		if(!$this->admin) {
			//check fo see if user can see all hosts and services 
			$this->sees_all = ($this->authKeys['authorized_for_all_hosts'] == true && $this->authKeys['authorized_for_all_services']) ? true : false; 
			//build auth objects array 
			$this->build_authorized_objects(); 
		}
		//print_r($this->authHosts); 
	
	}
	
	private function get_user()
	{	
		// HTTP BASIC AUTHENTICATION through Nagios Core or XI 
		//$remote_user="";
		if(isset($_SERVER["REMOTE_USER"]))
		{	
			$remote_user=$_SERVER["REMOTE_USER"];
			//echo "REMOTE USER is set: $remote_user<br />";
			return $remote_user;
		}
		//digest authentication 
		elseif(isset($_SERVER['PHP_AUTH_USER']))
		{
			//echo "Auth Digest detected".$_SERVER['PHP_AUTH_USER'];
			return $_SERVER['PHP_AUTH_USER'];
		}
		else
		{
			echo "Access Denied: No authentication detected.";
			return false; 
		}	
	 
	}	
	
	////////////////////////////////////////////////////////////
	//$username is obtained from $_SERVER authorized user for nagios 
	//
	private function set_perms()
	{
		global $NagiosData;
		$permissions = $NagiosData->getProperty('permissions');
	
		foreach($permissions as $key => $array) {
			foreach($array as $user) {
				if($user == $this->username || $user == '*') $this->authorize($key);
			}				
		}
	}
	//////////////////////////////////////////////////////
	//
	//activates authorization for user.  See authorizations.inc.php for auth list 
	//
	private function authorize($auth) //sets global permission 
	{
		global $authorizations; //global authorization array controller 
		$authorizations[$auth] = 1;
		$this->authKeys[$auth] = true; 
	}
	
	///////////////get methods 
	public function get_authorized_hosts() {
		return $this->authHosts; 
	}
	
	public function get_authorized_services() {
		return $this->authServices; 
	}
	
	public function get_username() {
		return $this->username; 
	}	
	
	public function is_admin() {
		return $this->admin; 
	}
	
	public function if_has_authKey($key) {
		if(isset($this->authKeys[$key]))
			return $this->authKeys[$key]; 
		else return false; 	
	}
	

	private function determine_admin() {
		$bool = true;
		foreach($this->authKeys as $key)
		{
			if($key != true) return false; 
		}
		return true; 
		
	}
	
	
	public function setAuthKey($keyname,$value) {
		if(isset($this->authKeys[$keyname])) {
			$this->authKeys[$keyname] = $value; 
		}	
	}
	
	//returns boolean 
	public function is_authorized_for_host($hostname) {
		//echo "checking auth <br />"; 
		//can user see everything? 
		if($this->admin == true || $this->sees_all == true) return true;  
		//user level filtering 
		if(array_key_exists($hostname,$this->authHosts) ) return true; 
		//not authorized 
		//echo "auth failed!<br />"; 
		return false; 
	}
	
	//returns boolean 
	public function is_authorized_for_service($hostname,$service) {
		//can user see everything? 
		if($this->admin == true || $this->sees_all == true) return true;  
		//user level filtering 
		
		if(isset($this->authHosts[$hostname]) && in_array($service,$this->authHosts[$hostname]['services']) ) return true; 
		//not authorized 

		return false; 
	}
	
	//main logic function for user-level filtering 
	private function build_authorized_objects() {
		global $NagiosData;
			
		//fetch necessary object config arrays 
		$hosts = $NagiosData->getProperty('hosts_objs');
		$contactgroups = $NagiosData->getProperty('contactgroups'); 
		
		//contactgroup memberships 
		$cg_memberships = array(); 
		
		//find relevant contact groups for user 
		foreach($contactgroups as $cg)
		{
			//echo $cg['contactgroup_name']; 
			if(strpos($cg['members'],$this->username)!==false) 
				$cg_memberships[] = $cg['contactgroup_name']; 			
		}
		
		//echo "CG Memberships<br />"; 
		//print_r($cg_memberships); 
		
		//check host for host->contact and host->contactgroup relationships 
		
		//////////////CREATE SINGLE MULTI-D HEIRARCHY ARRAY 
		/*
		//	$authObjects = 
			array ( 'localhost'	array(
		//										'host_name' => 'localhost'
		//										'services'	=> array( 0 => service1
																			 1 => service2
																			 3 => service3 )
		//										) 
		*/
		
		
		foreach($hosts as $host)
		{
			$key = $host['host_name']; 
			if(isset($host['contacts']) && strpos($host['contacts'],$this->username) !== false)
			{
				if(!isset($this->authHosts[$key])) $this->authHosts[$key] = array('host_name' => $key, 'services' => array() ); 
				$this->authHosts[$key]['host_name'] = $key; 
				continue; //skip to next 
			}	
			if(isset($host['contact_groups']))
			{
				$cgmems = explode(',',$host['contact_groups']);
				foreach($cgmems as $cg)
				{
					if(in_array($cg,$cgmems)) 
					{
						$this->authHosts[$key]['host_name'] = $key; 
						break; 
					}	//end IF
				
				}	//end FOREACH contactgroup member
			}//end IF contactgroups set 	
		
		}//end FOREACH host 
		
		//get services objects 		
		$services = $NagiosData->getProperty('services_objs');		
		//echo "Services: <br /><pre>".print_r($services,true)."</pre>"; 
		
		foreach($services as $service)
		{
			//$auth = false; 
			$key = $service['host_name']; 
			//check for authorized host first, if host is authorized add services  
			if(array_key_exists($key,$this->authHosts)) 
			{
				if(!isset($this->authHosts[$key])) $this->authHosts[$key] = array('host_name' => $key, 'services' =>array() ); 
				if(!isset($this->authHosts[$key]['services'])) $this->authHosts[$key]['services'] = array(); 
				
				//only add service if it's not already there 
				if(!in_array($service['service_description'], $this->authHosts[$key]['services'])) 
					$this->authHosts[$key]['services'][] = $service['service_description']; 
			}
			
			//check for authorization at the service level 
			if(isset($service['contacts']) && strpos($service['contacts'],$this->username) !== false)
			{
				//if(!isset($this->authHosts[$key])) $this->authHosts[$key] = array(); 
				if(!in_array($service['service_description'], $this->authHosts[$key]['services'])) 
					$this->authHosts[$key]['services'][] = $service['service_description']; 
				continue; 
			}
			
			//check against contactgroups 
			if(isset($service['contact_groups']) )
			{
				$cgmems = explode(',',$service['contact_groups']);
				foreach($cg_memberships as $cg)
				{
					if(in_array($cg,$cgmems)) 
					{
						//echo "key is: $key<br />";  
						$this->authHosts[$key]['services'][] = $service['service_description']; 
						break; 
					}	//end IF		
				}	//end FOREACH contactgroup member			
			} //end IF contactgroups 			
		} //end services FOREACH 
	
	}//end function build_authorized_objects() 
	

		
	
	
} //end NagiosUser class 





?>