<?php if (!defined('APPLICATION')) {
    exit();
}
use RoleModel;

if (!isset($Drop)) {
    $Drop = false;
}

if (!isset($Explicit)) {
    $Explicit = false;
}

$Database = Gdn::database();
$SQL = $Database->sql();

$Construct = $Database->structure();
$Px = $Database->DatabasePrefix;

// Role Table
$Construct->table('Role');

$RoleTableExists = $Construct->tableExists();
$RoleTypeExists = $Construct->columnExists('Type');

// Add a topcoder role type
if($RoleTableExists && $RoleTypeExists) {
    $Construct
        ->primaryKey('RoleID')
        ->column('Name', 'varchar(100)')
        ->column('Description', 'varchar(500)', true)
        ->column('Type', [TopcoderPlugin::ROLE_TYPE_TOPCODER, RoleModel::TYPE_GUEST, RoleModel::TYPE_UNCONFIRMED, RoleModel::TYPE_APPLICANT, RoleModel::TYPE_MEMBER, RoleModel::TYPE_MODERATOR, RoleModel::TYPE_ADMINISTRATOR], true)
        ->column('Sort', 'int', true)
        ->column('Deletable', 'tinyint(1)', '1')
        ->column('CanSession', 'tinyint(1)', '1')
        ->column('PersonalInfo', 'tinyint(1)', '0')
        ->set(true, false);
}
