<?php //NagiosUser.php  nagios user class to handle authorized hosts, services, and admin functionality 




class NagiosUser
{
	global $NagiosData; 
	private static $instance; 
	
	//boolean for users who can see and access all features 
	protected $admin = false; 

	//array for storing global authorizations from cgi file
	protected $authKeys = array(
		'authorized_for_all_host_commands' = false;
		'authorized_for_all_hosts' = false;
		'authorized_for_all_service_commands' = false;
		'authorized_for_all_services' = false;
		'authorized_for_configuration_information' = false;
		'authorized_for_system_commands' = false;
		'authorized_for_system_information' = false;
		'authorized_for_read_only' = true;	
		);
	
	protected $authHosts = array(); 
	protected $authServices = array(); 
	protected $authHostgroups = array(); 
	protected $authServicegroups = array(); 
	
	///////////////get methods 
	public function get_authorized_hosts() {
		return $this->authHosts; 
	}
	
	public function get_authorized_services() {
		return $this->authServices; 
	}
	
	public function get_authorized_hostgroups() {
		return $this->authHostgroups; 
	}
	
	public function get_authorized_servicegroups() {
		return $this->authServicegroups; 
	}
	
	public function is_admin() {
		return $admin; 
	}
	
	public function if_has_authKey($key) {
		if(isset($this->authKeys[$key]))
			return $this->authKeys['authorized_for_all_hosts']; 
		else return false; 	
	}
	
	
	/////////////add/set methods ///////////////////////////	
	public add_authorized_host($hostname='') {
		if($hostname !='') $this->authHosts[] = $hostname; 
	}
	
	public function add_authorized_service($hostname='',$service='',$hostgroup=false) {
		if($hostgroup && $service !='') {
			//add logic if it's a service->hostgroup assignment 
		}	
		elseif($hostname!='',$service='') {  //normal host:service addition 
			$this->authServices[] = $hostname.'::'.$service;  
		}
		else return; 
	}
	
	public function add_authorized_hostgroup($hostgroup='') {
		if($hostgroup !='') {
			$this->authHostgroups[] = $hostgroup; 
			//grab list of all host members of this host group and and array push into authHosts 
		}			
	}
	
	public function add_authorized_servicegroup($servicegroup='') {
		if($servicegroup!='') {
			$this->authServicegroups[] = $servicegroup;
			//grab list of all service members of this group and push into authServices array 
		}
	}
	
	public function setAuthKey($keyname,$value) {
		if(isset($this->authKeys[$keyname])) {
			$this->authKeys[$keyname] = $value; 
		}	
	}
	
	
	
	
	
}





?>