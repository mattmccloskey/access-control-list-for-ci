ACL Library for CodeIgniter
==========================

"Powerful things require access control. Access control lists are a way to manage application permissions in a fine-grained, yet easily maintainable and manageable way."

You can find a very good in-depth introduction to ACL here: http://book.cakephp.org/2.0/en/core-libraries/components/access-control-lists.html

This library will get you up and running with an ACL in CodeIgniter quickly and easily.

#### Key Concepts
- An ACL consists of Access Request Objects (Things that want stuff) and Access Control Objects (Things that are wanted). For short, we call these AROs and ACOs.
- Both AROs and ACOs can be children of other AROs and ACOs. For example, my family (which includes me) might have access to the country club (which includes a restaurant). So we can change access for the entire family at once, or single me out and deny me access to the entire country club, or just the restaurant.
- Access is assumed denied until proven otherwise. So if we check for my access to the restaurant and get no answer, then the library will check my family's access to the restaurant. If we still get no answer we'll check my family's access to the whole country club. If my family has access to the country club, then because I'm a child of the family, and the restaurant is a child of the country club, I get in.

## Usage
#### First, create your database tables. This library requires three tables.
1. A list of Access Request Objects. (Like users, accounts, api keys, etc)
```
CREATE TABLE `acl_aros` (  
	`id` int(11) NOT NULL auto_increment,  
	`parent_id` int(11) default NULL,  
	`title` varchar(40) default NULL,  
	`model` varchar(40) default NULL,  
	`foreign_key` int(11) unsigned default NULL,  
	`description` tinytext,  
	PRIMARY KEY  (`id`)  
) ENGINE=MyISAM AUTO_INCREMENT=0 DEFAULT CHARSET=utf8
```
2. A list of Access Control Objects. (Like secure areas, features, or even read/write permission)
```
CREATE TABLE `acl_acos` (  
	`id` int(11) NOT NULL auto_increment,  
	`parent_id` int(11) default NULL,  
	`title` varchar(40) default NULL,  
	`model` varchar(40) default NULL,  
	`foreign_key` int(11) unsigned default NULL,  
	`description` tinytext,  
	PRIMARY KEY  (`id`)  
) ENGINE=MyISAM AUTO_INCREMENT=0 DEFAULT CHARSET=utf8
```
3. A list of permissions (Does ARO x have access to ACO y?)
```
CREATE TABLE `acl_permissions` (  
	`id` int(11) NOT NULL auto_increment,  
	`aro_id` int(11) default NULL,  
	`aco_id` int(11) default NULL,  
	`access` varchar(20) default NULL,  
	PRIMARY KEY  (`id`)  
) ENGINE=MyISAM AUTO_INCREMENT=0 DEFAULT CHARSET=latin1
```

#### Now assign some permissions
In this library, AROs and ACOs are called objects, and are primarily referenced by a model/foreign_key pair. For example a user (that's the model) with ID 1 (that's the foreign key).


So let's give User id 1 access to Account id 1
```
$this->acl->allow(array('user', 1), array('account', 1));

// NOTE: allow() will automatically create the ARO and ACO objects if they don't already exist
```

Alternately, we could assign User 1 as a child of a group, and then say that group can access Account 1. This allows us to blanket all users under that group with access to Account 1
```
// Create the objects (assuming they don't already exist)
// There's no danger here as this won't create duplicates
$this->acl->create_object('aro', array('group', 1));
$this->acl->create_object('aro', array('user', 1));
$this->acl->create_object('aco', array('account', 1));

// Make user 1 a child of group 1
$this->acl->set_parent('aro', array('user', 1), array('group', 1));

// Allow group 1 access to account 1
$this->acl->allow(array('group', 1), array('account', 1));
```

We can also deny specific AROs access to specific ACOs. Let's say we have another user (id 2) who's a member of group 1. We want user 2 to remain a member of group 1, but he can no longer access account 1, while retaining all other rules that govern group 1.
```
$this->acl->deny(array('user', 2), array('account', 1));
```

#### Now check permissions
Now that permissions are assigned, checking for access is easy. 

```
// User 1 is logged in and trying to access account 1.
if( ! $this->acl->check(array('user', 1), array('account', 1)))
{
	// They don't have access, redirect the user or whatever...
}
```

## OK, on with the full reference

#### check($aro, $aco)
Checks an ARO for access to an ACO

#### allow($aro, $aco)
Give an ARO access to an ACO

#### deny($aro, $aco)
Deny an ARO access to an ACO

#### unset_access($aro, $aco)
Set permission to blank. Useful if a child ARO has different permissions than it's parent for a given ACO, and you want to lift that to have the parent   permissions apply.

#### create_object($kind, $object)
Create an ARO or ACO   
(NOTE: this happens automatically when using allow() or deny()).  
$kind should be either 'aro' or 'aco'

#### set_parent($kind, $object)
Assign an object's parent  
$kind should be either 'aro' or 'aco'

#### get_object($kind, $object)
Returns the object ID of an ARO or ACO  
$kind should be either 'aro' or 'aco'

#### delete_object($kind, $object)
Deletes an ARO or ACO  
$kind should be either 'aro' or 'aco'

### To be continued...
There's quite a few more functions in there, which you can peruse yourself. These should get you started!
