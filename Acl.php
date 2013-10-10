<?php if ( ! defined('BASEPATH')) exit('No direct script access allowed'); 


/* Acl
Manage Access Control Lists

Methods:
---------------------------------------------
check - Checks for access.

Description:
check(mixed $aro, mixed $aco[, mixed $action)
		
Parameters
$aro 		int, string, or array. Int, or ctype_digit checks ARO id, 
			string checks ARO title, and array checks model/foreign_key
$aco 		int, string, or array. Int, or ctype_digit checks ARO id, 
			string checks ARO title, and array checks model/foreign_key
$action		If specified, check() will return boolean if the passed 
			action is found in the access field.
			If not specified, check() will simply return the found access 
			field.

---------------------------------------------
allow - Allows an ARO access to an ACO

Description:
allow(mixed $aro, mixed $aco[, $action]);

Parameters
$aro 		int, string, or array. Int, or ctype_digit checks ARO id, 
			string checks ARO title, and array checks model/foreign_key
$aco 		int, string, or array. Int, or ctype_digit checks ARO id, 
			string checks ARO title, and array checks model/foreign_key
$action		If not specified: give a blanket allow
			If specified, access field will be set

---------------------------------------------
deny - denies an ARO access to an ACO

Description:
deny(mixed $aro, mixed $aco[, $action]);

Parameters
$aro 		int, string, or array. Int, or ctype_digit checks ARO id, 
			string checks ARO title, and array checks model/foreign_key
$aco 		int, string, or array. Int, or ctype_digit checks ARO id, 
			string checks ARO title, and array checks model/foreign_key
$action		If not specified: give a blanket deny

---------------------------------------------
delete - delete records for ARO/ACO pair

Description:
deny(mixed $aro, mixed $aco[, $action]);

Parameters
$aro 		int, string, or array. Int, or ctype_digit checks ARO id, 
			string checks ARO title, and array checks model/foreign_key
$aco 		int, string, or array. Int, or ctype_digit checks ARO id, 
			string checks ARO title, and array checks model/foreign_key
$action		If not specified: delete entry
			If specified, action will be removed from access field.
				

Objects can be in groups, groups can have parent groups. Objects should be unique.




CREATE TABLE SYNTAX
---------------------------------------------
CREATE TABLE `acl_acos` (
  `id` int(11) NOT NULL auto_increment,
  `parent_id` int(11) default NULL,
  `title` varchar(40) default NULL,
  `model` varchar(40) default NULL,
  `foreign_key` int(11) unsigned default NULL,
  `description` tinytext,
  PRIMARY KEY  (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=0 DEFAULT CHARSET=utf8


CREATE TABLE `acl_aros` (
  `id` int(11) NOT NULL auto_increment,
  `parent_id` int(11) default NULL,
  `title` varchar(40) default NULL,
  `model` varchar(40) default NULL,
  `foreign_key` int(11) unsigned default NULL,
  `description` tinytext,
  PRIMARY KEY  (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=0 DEFAULT CHARSET=utf8

CREATE TABLE `acl_permissions` (
  `id` int(11) NOT NULL auto_increment,
  `aro_id` int(11) default NULL,
  `aco_id` int(11) default NULL,
  `access` varchar(20) default NULL,
  PRIMARY KEY  (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=0 DEFAULT CHARSET=latin1
---------------------------------------------
*/

class Acl {

	var $msg		= '';		// Class message
	var $CI			= false; 	// Used for the Code Igniter Instance
	var $DB 		= false; 	// Used to access the Database
	var $tables 	= array(
		"acl" 			=> "acl_permissions",
		"aro" 			=> "acl_aros",
		"aco" 			=> "acl_acos",
		"aco_actions" 	=> "acl_aco_actions",
		"aro_actions"	=> "acl_aro_actions"
	);
	var $action_model	= "acl_action"; // the model to store actions as
	
	var $permission_id	= false;	// stores the last id from the acl table
	
	var $verified = array("aco" => array(), "aro" => array());
	
	var $last_objects = array("aco" => false, "aro" => false);
	
	var $object_cache = array('aco' => array(), 'aro' => array());
	
	var $access_cache = array();
	
    function Acl()
    {
    	// Initialize
    }
    
    
    // ---------------------------------------------------------------------------------------
    /* Methods for checking access
    */
    
    
    // --------------------------------------------------------------------
    	
    /**
     * Main check function to check access
     *
     * @param 	mixed 	$aro - The Access Request Object. Can be anything accepted by get_object()
     * @param 	mixed 	$aco - The Access Control Obejct. Can be anything accepted by get_object()
     * @param 	string 	$action (optional) - Check a specific action. If specified, functino will return boolean
     *
     * @return 	mixed	Returns boolean, or action string if $action is not specified. Boolean if $action is specified.
     * 
     */
    function check($aro, $aco, $action=false)
    {

    	$access = false;
    	
    	// Resolve passed info to ARO and ACO objects
    	$aro = $this->get_object("aro", $aro);
    	$aco = $this->get_object("aco", $aco);
    	    	    	
    	// Has to be existing records. If either don't exist, return false
    	if($aro == false || $aco == false)
    	{
    		return false;
    	}
    	
    	// Cache key to avoid multiple requests for the same things.
    	$cache_key = $aro['id'].'.'.$aco['id'];
    	if($action) $cache_key .= '.'.$action;
    	if(isset($this->access_cache[$cache_key]))
    	{
    		return $this->access_cache[$cache_key];
    	}
    	
    	
    	// Loop ARO's till we find a match or run out of parents
    	$check_aro = $aro['id'];
    	while($check_aro != false && $access === false)
    	{
    		// walk up the ACO tree to find a match
    		$check_aco = $aco['id'];
    		while($check_aco != false && $access === false)
    		{
    			// Check access
    			$access = $this->_check_access($check_aro, $check_aco, $action);
    			
    			// Get ACO parent, and repeat
    			$check_aco = $this->get_parent("aco", $check_aco);
    		}
    		
    		// Get ARO parent, and repeat
    		$check_aro = $this->get_parent("aro", $check_aro);
    	}
    	
    	// Cache the result
    	$this->access_cache[$cache_key] = $access;
    	
    	return $access;
    }
    
    
    
    
    // --------------------------------------------------------------------
    	
    /**
     * Check for specified access - based on acl id's
     *
     * @param 	int		$aro - The Access Requet Object ID
     * @param	int		$aco - The Access Control Object ID
     * @param	string	$action (optional) - The action to check for
     *
     * @return	boolean
     */
     
    function _check_access($aro, $aco, $action = false)
    {
    	$this->get_database();
    	
    	// If an action is passed, make sure it exists
    	if($action)
    	{
    		$action = $this->get_action_object($aco, $action);
    		if( ! $action) return false;
    	}
    	
    	$aro = $this->get_object('aro', $aro);
    	$aco = $this->get_object('aco', $aco);
    	
    	if( ! $aro OR ! $aco)
    	{
    		return false;
    	}
    	
    	// proceed check
    	$access = false;
    	    	
    	$table = $this->tables['acl'];
    	$query = $this->DB->query("SELECT id, access FROM $table WHERE aro_id = '".$aro['id']."' AND aco_id = '".$aco['id']."' LIMIT 1");
    
    	if($query->num_rows() == 1)
    	{
    		$row = $query->row();
    		$access = $row->access;
    	}
    	
    	// If an action is passed (And access is not 0), Check the entry against the action
		if($action !== false && ($access == 1 OR $access === false))
    	{
    		// check access against the action aco
	    	$access = $this->_check_access($aro, $action);
    	}
    	
    	return $access;
    }
    
    
    
    
    
    
    // --------------------------------------------------------------------
    	
    /**
     * Check a match - Match an action to an access entry, return boolean
     * 
     * @param	string	$access - The access field
     * @param	string	$action - The passed action
     *
     * @return 	Boolean
     * 
     */
    function _check_match($access, $action)
    {    	
    	
		// if there is an action, we want to return boolean for weather it exists.
		if(preg_match('/(^|\/)'.$action.'($|\/)/', $access))
		{
			return true;
		}
		else
		{
			return false;
		}
    	
    }
    
    
     
    // --------------------------------------------------------------------
    	
    /**
     * Parse Object Info - 	Accept a mixed var and create an associative
     *						array with field names and values.
     * 
     * @param 	mixed 	$info - Info to parse
     * 
     * @return	array	An associative array (fieldname => value)
     */
    function parse_object_info($info)
    {
    	$this->get_database();
    	
    	$this->CI->load->helper('array');
    	
    	$new_info = array();
    	
    	$fields = array("model", "foreign_key", "title", "id", "parent_id", "description");
		/*
		// Table Format:
		"id" => ""
		"parent_id" => "", (currently not used)
		"title" => "",
		"model" => "",
		"foreign_key" => "",
		"description" => ""
		*/
		
		if(is_int($info))
		{
			$new_info['id'] = $info; // Must be an id
		}
    	
    	else if(is_string($info))
    	{
    		// If it's an id
    		if(ctype_digit($info))
    		{
    			$new_info['id'] = $info;
    		}
    		
    		// Must be a title
    		else
    		{
    			$new_info['title'] = $info;
    		}
    	}
    	
    	else if($this->is_assoc($info))
    	{
    		foreach($fields as $value)
    		{
    			if(array_key_exists($value, $info)) $new_info[$value] = $info[$value];
    		}
    	}
    	
    	else if(is_array($info))
    	{
    		foreach($info as $key => $value)
    		{
    			$new_info[$fields[$key]] = $value;
    		}
    	}
    	
    	return $new_info;
    }
    

    
    // --------------------------------------------------------------------
    	
    /**
     * Resolve Object - Takes info about an object and finds the table id
     *
     * @param 	string 	$kind - The kind of Object ("aro" or "aco")
     * @param 	mixed	$info - The info about the object. Anything accepted by $this->parse_object_info()
     * @param	boolean	$create - Weather or not to create the object if it can't be found
     *
     * @return	mixed	The table id, or false if it doesn't exist.
     * 
     */
    function get_object($kind, $info, $create = false)
    {
    	$this->get_database();
    	    	
    	/*	
    		1. Parse object info
    		2. Look for object with matching info
    		3. Return Array Object
    	*/
    	
    	$object = false;
   
    	$info = $this->parse_object_info($info);
    	
    	$object_key = md5(serialize($info));
    	
    	if(isset($this->object_cache[$kind][$object_key]))
    	{
    		return $this->object_cache[$kind][$object_key];
    	}
 
    	if(isset($info['id']) && array_key_exists($info['id'], $this->verified[$kind]))
    	{
    		return $this->verified[$kind][$info['id']];
    	}
    	
    	$this->DB->where($info);
    	$query = $this->DB->get($this->tables[$kind], 1);
    	
    	if($query->num_rows() == 1)
    	{
    		$object = $query->row_array();
    	}
    	
    	// See if we should create the object
    	if($object === false && ! array_key_exists("id", $info) && $create === true)
    	{
    		$object = $this->get_object($kind, $this->create_object($kind, $info));
    	}
    	
    	if($object !== false)
    	{
    		// Save the object to verfied array
	    	$this->verified[$kind][$object['id']] = $object;
	    	
	    	// Save the object to the cache based on the requested object md5
	    	$this->object_cache[$kind][$object_key] = $object;
    	}
    	
    	// Set this as the last object
    	$this->last_objects[$kind] = $object;
    	
    	return $object;
    }
    
    /* Object shortcuts */
    function get_aro($info, $create = false)
    {
    	return $this->get_object('aro', $info, $create);
    }
    
    function get_aco($info, $create = false)
    {
    	return $this->get_object('aco', $info, $create);
    }
    
    function get_aro_id($info, $create = false)
    {
    	$object = $this->get_object('aro', $info, $create);
    	return $object['id'];
    }
    
    function get_aco_id($info, $create = false)
    {
    	$object = $this->get_object('aco', $info, $create);
    	return $object['id'];
    }
    
    
    // --------------------------------------------------------------------
    	
    /**
     * Get Action Object
     * 
     */
    function get_action_object($aco, $action)
    {
    	$aco = $this->get_object('aco', $aco);
    	if( ! $aco) return false;
    	
    	return $this->get_object('aco', array("model" => $this->action_model, "parent_id" => $aco['id'], "title" => $action), true);
    }
    
    
    
    
    // --------------------------------------------------------------------
    	
    /**
     * Create Object
     * 
     * @param	string 	$kind - The object kind ("aro" or "aco")
     * @param	mixed	$info - Anything accepted by $this->parse_object_info()
     *
     * @return	int		The object ID
     */
    function create_object($kind, $info)
    {
    	$check = $this->get_object($kind, $info);
    	if($check)
    	{
    		return $check['id'];
    	}
    	
    	$this->get_database();
    	$this->DB->insert($this->tables[$kind], $this->parse_object_info($info));
    	return $this->DB->insert_id();
    }
    
    /* Shortcuts */
    function create_aco($info)
    {
    	return $this->create_object('aco', $info);
    }
    function create_aro($info)
    {
    	return $this->create_object('aro', $info);
    }
    
    
    
    
    
    // --------------------------------------------------------------------
    	
    /**
     * Delete Object
     *
     * @param 	string	$kind - The object kind ("aro" or "aco")
     * @param	mixed	$info - Anything accepted by $this->parse_object_info()	
     * 
     * @return	boolean
     */
    function delete_object($kind, $info)
    {
    	$object = $this->get_object($kind, $info);
    	
    	if( ! $object) return true;
    	
    	// delete the object
    	if( ! $this->DB->delete($this->tables[$kind], array("id" => $object['id'])))
    	{
    		return false;
    	}
    	
    	// Set the children to the parent if it exists
    	$parent = $this->get_parent($kind, $info);
    	if( ! $parent) $parent = '';
    	$this->DB->set('parent_id', $parent);
    	$this->DB->where('parent_id', $object['id']);
    	$this->DB->update($this->tables[$kind]);
    	
    	// delete permissions
    	if( ! $this->DB->delete($this->tables['acl'], array($kind."_id" => $object['id'])))
    	{
    		return false;
    	}
    	
    	return true;
    }
    /* shortcuts */
    function delete_aro($info)
    {
    	return $this->delete_object('aro', $info);
    }
    function delete_aco($info)
    {
    	return $this->delete_object('aco', $info);
    }
    
    
    
    
    // --------------------------------------------------------------------
    	
    /**
     * Update Object
     *
     * @param 	string	$kind - The object kind ("aro" or "aco")
     * @param	int		$id - The object id
     * @param	mixed	$info - Anything accepted by $this->parse_object_info()	
     * 
     * @return	boolean
     */
    function update_object($kind, $id, $info)
    {
    	$this->get_database();
    	
    	$this->DB->set($info);
    	$this->DB->where('id', $id);
    	$query = $this->DB->update($this->tables[$kind]);
    	
    	return $query;
    }
    
    /* shortcuts */
    function update_aro($id, $info)
    {
    	return $this->update_object('aro', $id, $info);
    }
    function update_aco($id, $info)
    {
    	return $this->update_object('aco', $id, $info);
    }

        
    
    
   
    
    // --------------------------------------------------------------------
    	
    /**
     * Get and object's parent
     *
     * @param	string	$kind - The object kind ("aro" or "aco")
     * @param	mixed	$info - The object ID, or anything accepted by $this->parse_object_info
     *
     * @return	mixed	The parent id or false
     * 
     */
    function get_parent($kind, $info)
    {
    	$object = $this->get_object($kind, $info);
    	
    	if( ! $object) return false;
    	
    	$table = $this->tables[$kind];
    	$query = $this->DB->query("SELECT parent_id FROM $table WHERE id = '".$object['id']."' LIMIT 1");
    	if($query->num_rows() == 0)
    	{
    		return false;
    	}else{
    		$row = $query->row();
    		return $row->parent_id;
    	}
    }
    
    function get_aro_parent($info)
    {
    	return $this->get_parent('aro', $info);
    }
    
    function get_aco_parent($info)
    {
    	return $this->get_parent('aco', $info);
    }
    
    
    
    
    // --------------------------------------------------------------------
    	
    /**
     * Set an Objects Parent
     * 
     */
    function set_parent($kind, $child, $parent)
    {
    	$child = $this->get_object($kind, $child);
    	$parent = $this->get_object($kind, $parent);
    	
    	if( ! $child)
    	{
    		// Can't find child
    		return false;
    	}
    	
    	// Set parent
    	$parent_id = $parent ? $parent['id'] : '';
    	$this->DB->set('parent_id', $parent_id);
    	$this->DB->where('id', $child['id']);
    	$query = $this->DB->update($this->tables[$kind]);
    	
    	return $query;
    }
    
    function set_aro_parent($child, $parent)
    {
    	$this->set_parent("aro", $child, $parent);
    }
    
    function set_aco_parent($child, $parent)
    {
    	$this->set_parent("aco", $child, $parent);
    }
    
    
    
    
    
    // --------------------------------------------------------------------
    	
    /**
     * Get top parent. Get the upper most parent
     * 
     */
 	function get_top_parent($kind, $info)
 	{
 		while($parent = $this->get_parent($kind, $info))
 		{
 			$info = $parent;
 		}
 		
 		return $info;
 	}
	
	
	
	
	// ---------------------------------------------------------------------------------------
	/* Methods for changing access
	*/
	
	
	// --------------------------------------------------------------------
		
	/**
	 * Allow Access
	 * 
	 */
	function allow($aro, $aco, $action = 1)
	{
		return $this->set_access($aro, $aco, $action);
	}
	
	
	
	// --------------------------------------------------------------------
		
	/**
	 * Deny Access
	 * 
	 */
	function deny($aro, $aco, $action = 0)
	{
		if(is_string($action) && $action != '')
		{
			$aco = $this->get_action_object($aco, $action);
			$action = 0;
		}
		
		return $this->set_access($aro, $aco, $action);
	}
	
	
	
	
	
	// --------------------------------------------------------------------
		
	/**
	 * Set Access (Update access entry. Currently auto creates objects).
	 * 
	 */
	function set_access($aro, $aco, $access = 1)
	{		
		/*
		1. If action is string, check to see if it exists, update or create.
		2. If Not, update, or create.
		*/
		
		$this->get_database();
		
		// Resolve passed info to ARO and ACO objects
    	$aro = $this->get_object("aro", $aro, true);
    	$aco = $this->get_object("aco", $aco, true);
    	
    	// make sure we have both and aro and an aco
    	if($aro == false || $aco == false)
    	{
    		return false;
    	}
    	
    	// convert access
    	if($access === true) $access = 1;
    	if($access === false) $access = 0;
    	
    	// if $access is a string, get the aco action object and set for that.
    	if(is_string($access) && $access != '')
    	{
    		$action = $this->get_action_object($aco, $access, true);
    		
    		// set access for $aco to 1, otherwise, the action won't matter.
    		$this->set_access($aro, $aco, 1);
    		
    		// set access for the action
    		return $this->set_access($aro, $action, 1);
    	}
    	
    	// if access is 0, unset all the actions
    	if($access === 0)
    	{
    		$actions = $this->get_actions($aco);
			foreach($actions as $action)
			{
				$this->unset_access($aro, $action['id']);
			}
    	}
    	
    	// Run the queries
    	$data = array(
			"access" => $access
		);
		$where = array(
			"aro_id" => $aro['id'], 
			"aco_id" => $aco['id']
		);
		
		// See if there's an entry
		$this->DB->where($where);
		$check = $this->DB->get($this->tables['acl'], 1);
		
		if($check->num_rows() == 0)
		{
			// insert
			$this->DB->set(array_merge($data, $where));
    		$query = $this->DB->insert($this->tables['acl']);
		}
		else
		{
			// update
			$this->DB->set($data);
    		$this->DB->where($where);
    		$query = $this->DB->update($this->tables['acl']);
		}
		
		return $query;
	}
	
	
	
	
	// --------------------------------------------------------------------
		
	/**
	 * Delete access permissions
	 * 
	 */
	function unset_access($aro, $aco, $action = false)
	{
		// Resolve passed info to ARO and ACO into ids
    	$aro = $this->get_object("aro", $aro);
    	$aco = $this->get_object("aco", $aco);
    	
    	if($action !== false && is_string($action) && $action != '')
    	{
    		$aco = $this->get_action_object($aco, $action);
    	}
    	
    	if($aro == false || $aco == false)
    	{
    		// record didn't exist in the first place
    		return true;
    	}
    	
    	if( ! $action)
    	{
    		// delete permissions for actions under the aco
       		$actions = $this->get_actions($aco);
       		foreach($actions as $action)
       		{
       			$this->unset_access($aro, $aco, $action['title']);
       		}
    	}
    	
    
		// delete acl table record
		$this->DB->where(array("aro_id" => $aro['id'], "aco_id" => $aco['id']));
		$delete = $this->DB->delete($this->tables['acl']);
    	
    	return true;
	}
	
	
	
	
	// ---------------------------------------------------------------------------------------
	/* Utilities
	*/
	
	/* Return the database (Used becase of PHP 4, since we can't do this in the constructor) NOTE: Should update this... */
    function get_database(){
    	if($this->DB == false)
    	{
    		// Get CI instance
	    	$this->CI =& get_instance();
	    	
	    	// Additional functionality to keep ACL in a different database than the one auto loaded
	    	// $this->DB = $CI->load->database('', true);
	    	
	    	// Otherwise get main database from CI instance
	    	$this->DB =& $this->CI->db;
	    }
    }
    
    /* Is the array associative? */
    function is_assoc($_array)
	{ 
		if ( !is_array($_array) || empty($_array) ) 
		{ 
			return false; 
		} 
		foreach (array_keys($_array) as $k => $v) 
		{ 
			if ($k !== $v) 
			{ 
				return true; 
			} 
		} 
		return false; 
	}
    
    
    /* Prep Value - replace anything not alpha numeric */
    function prep_value($value)
	{
		// replace illegal characters
		$value = strtolower(trim($value));
		$value = preg_replace('/[^a-z0-9-]/', '-', $value);
		$value = preg_replace('/-+/', "-", $value);
		return $value;
	}
	
	
	
	// ---------------------------------------------------------------------------------------
	/* Methods for fetching information about Objects
	
	
	
	// --------------------------------------------------------------------
		
	/**
	 * Get object info
	 * 
	 */
	function get_object_info($kind, $info)
	{
		$object = $this->get_object($kind, $info);
		
		if( ! $object) return false;
		
		// count children
		$this->DB->select('id');
		$this->DB->where("parent_id", $object['id']);
		$query = $this->DB->get($this->tables[$kind]);
		
		$object['num_children'] = $query->num_rows();
		
		return $object;
	}
	
	/* shortcut functions */
	function get_aro_info($info)
	{
		return $this->get_object_info('aro', $info);
	}
	
	function get_aco_info($info)
	{
		return $this->get_object_info('aco', $info);
	}
	
	
	
	
	
	// --------------------------------------------------------------------
		
	/**
	 * List Object Tree
	 * 
	 */
	function get_tree($kind, $aro = false, $parent_id = NULL)
	{	
		$this->get_database();
		
		if($aro)
		{
			$aro = $this->get_object('aro', $aro);
		}
		
		$tree = array();
		
		$this->DB->where("parent_id", $parent_id);
		$this->DB->where("model !=", $this->action_model);
		$query = $this->DB->get($this->tables[$kind]);
		
		$tree = $query->result_array();
		
		foreach($tree as $key => $item)
		{
			if($aro)
			{
				$tree[$key]['access'] = $this->check($aro, $item['id']);
				$tree[$key]['access_entry'] = $this->_check_access($aro, $item['id']);
			}
			$tree[$key]['children'] = $this->get_tree($kind, $aro, $item['id']);
			$tree[$key]['actions'] = $this->get_actions($item['id'], $aro);
		}
		
		return $tree;
	}
	
	
	// --------------------------------------------------------------------
		
	/**
	 * Get Actions
	 * Get items stored as the action model
	 * 
	 */
	function get_actions($aco, $aro = false)
	{
		$this->get_database();
		
		$aco = $this->get_object('aco', $aco);
		if( ! $aco) return false;
		
		$this->DB->where('parent_id', $aco['id']);
		$this->DB->where('model', $this->action_model);
		$query = $this->DB->get($this->tables['aco']);
		
		$actions = $query->result_array();
		
		if($aro)
		{
			foreach($actions as $key => $value)
			{
				$actions[$key]['access'] = $this->check($aro, $aco, $value['title']);
 			}
		}
		return $actions;
	}
	
	
	
	// --------------------------------------------------------------------
		
	/**
	 * Get Objects
	 * 
	 */
	function get_objects($kind, $where = false)
	{
		$this->get_database();
		
		if($where) $this->DB->where($where);
		$query = $this->DB->get($this->tables[$kind]);
		
		return $query->result_array();
	}
	
	/* ARO shortcut */
	function get_aros($where = false)
	{
		return $this->get_objects('aro', $where);
	}
	
	/* ACO shortcut */
	function get_acos($where = false)
	{
		return $this->get_objects('aco', $where);
	}
	
	
	
	/* Get children */
	function get_children($kind, $parent, $where = false)
	{
		$parent = $this->get_object($kind, $parent);
		if( ! $where) $where = array();
		$where['parent_id'] = $parent['id'];
		return $this->get_objects($kind, $where);
	}
	
	function get_aro_children($parent, $where = false)
	{
		return $this->get_children('aro', $parent, $where);
	}
	
	function get_aco_children($parent, $where = false)
	{
		return $this->get_children('aco', $parent, $where);
	}
	
	
	
	
	// --------------------------------------------------------------------
		
	/**
	 * Last Objects - the last objects parsed by the class
	 * 
	 */
	function last_aro()
	{
		return $this->last_objects['aro'];
	}
	function last_aco()
	{
		return $this->last_objects['aco'];
	}
}
