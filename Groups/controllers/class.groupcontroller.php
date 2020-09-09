<?php
/**
 * Group controller
 */

use Vanilla\Message;

/**
 * Handles accessing & displaying a single group via /group endpoint.
 */
class GroupController extends VanillaController {

    /** @var GroupModel */
    public $GroupModel;

    /** @var Gdn_Form */
    public $Form;

    /** @var array Models to include. */
    public $Uses = ['Form', 'Database', 'GroupModel'];


    public function __construct() {
        parent::__construct();
        $this->GroupModel = new GroupModel();
    }

    public function initialize() {
        parent::initialize();

      //  $this->Menu->highlightRoute('/groups');
        $this->CssClass = 'NoPanel';
        /**
         * The default Cache-Control header does not include no-store, which can cause issues with outdated category
         * information (e.g. counts).  The same check is performed here as in Gdn_Controller before the Cache-Control
         * header is added, but this value includes the no-store specifier.
         */
        if (Gdn::session()->isValid()) {
            $this->setHeader('Cache-Control', 'private, no-cache, no-store, max-age=0, must-revalidate');
        }
    }

    /**
     * Default single group display.
     *
     * @since 2.0.0
     * @access public
     *
     * @param int $GroupID Unique group ID
     * @param string $GroupStub URL-safe title slug
     */
    public function index($GroupID = '') {
        // Setup head
         Gdn_Theme::section('Group');
        // Load the discussion record
        $GroupID = (is_numeric($GroupID) && $GroupID > 0) ? $GroupID : 0;
        if (!array_key_exists('Group', $this->Data)) {
            $this->setData('Group', $this->GroupModel->getID($GroupID), true);
        }

        if (!is_object($this->Group)) {
            $this->EventArguments['GroupID'] = $GroupID;
            $this->fireEvent('GroupNotFound');
            throw notFoundException('Group');
        }

        $this->setData('Breadcrumbs', [['Name' => t('Groups'), 'Url' => '/groups'],
            ['Name' => $this->Group->Name, 'Url' => '/group/'.$GroupID]]);
        $this->setData('CurrentUserGroups', $this->GroupModel->memberOf(Gdn::session()->UserID));
        $this->setData('TotalMembers', $this->GroupModel->countOfMembers($GroupID));
        $this->setData('Leaders', $this->GroupModel->getLeaders($GroupID));
        $this->setData('Members', $this->GroupModel->getMembers($GroupID,[],'',30,0));
        // Setup
        $this->title($this->Group->Name);

        $this->render();
    }

    /**
     * Create new group.
     *
     * @since 2.0.0
     * @access public
     */
    public function add() {
        //TODO: check permissions

        $this->title(t('New Group'));
        // Use the edit form with no groupid specified.
        $this->View = 'Edit';
        $this->edit();
    }


    /**
     * Remove a group.
     *
     * @since 2.0.0
     * @access public
     */
    public function delete($groupID = false) {
        //TODO: permissions
        $this->title(t('Delete Group'));

        $group = $this->GroupModel->getByGroupID($groupID);
       // Make sure the form knows which item we are deleting.
        $this->Form->addHidden('GroupID', $groupID);

        if ($this->Form->authenticatedPostBack()) {
            if ($this->Form->errorCount() == 0) {
                $this->GroupModel->delete($groupID);
                $this->setRedirectTo('/groups');
            }
        }
        $this->render();
    }

    /**
     * Edit a group.
     *
     * @param int|bool $groupID
     * @since 2.0.0
     * @access public
     */
    public function edit($groupID = false) {
        if ($this->title() == '') {
            $this->title(t('Edit Group'));
        }

        $this->Group = $this->GroupModel->getByGroupID($groupID);
        if(!$groupID) {
            $this->Group->OwnerID = Gdn::session()->UserID;
            $this->Group->LeaderID = Gdn::session()->UserID;
        }
        $this->setData('Breadcrumbs', [['Name' => t('Groups'), 'Url' => '/groups'],
            ['Name' => $this->Group->Name]]);

        // Set the model on the form.
        $this->Form->setModel($this->GroupModel);

        // Make sure the form knows which item we are editing.
        $this->Form->addHidden('GroupID', $groupID);
        $this->Form->addHidden('OwnerID', $this->Group->OwnerID);

        // If seeing the form for the first time...
        if ($this->Form->authenticatedPostBack() === false) {
            // Get the group data for the requested $GroupID and put it into the form.
            $this->Form->setData($this->Group);
        } else {

            // If the form has been posted back...
            $this->Form->formValues();
            $this->Form->saveImage('Icon');
            $this->Form->saveImage('Banner');
            if ($groupID = $this->Form->save()) {
                if ($this->deliveryType() === DELIVERY_TYPE_DATA) {
                    $this->index($groupID);
                    return;
                }
                $this->setRedirectTo('group/'.$groupID );
            }
        }

        $this->render();
    }


    /**
     * Create new group.
     *
     * @since 2.0.0
     * @access public
     */
    public function members($GroupID = '',$Page = false) {
        //TODO: check permissions
        $this->allowJSONP(true);
        Gdn_Theme::section('Group');
        $GroupID = (is_numeric($GroupID) && $GroupID > 0) ? $GroupID : 0;
        $Group = $this->GroupModel->getByGroupID($GroupID);

        // Determine offset from $Page
        list($Offset, $Limit) = offsetLimit($Page, c('Vanilla.Groups.PerPage', 30), true);
        $Page = pageNumber($Offset, $Limit);
        // Set canonical URL
        $this->canonicalUrl(url(concatSep('/', 'group/members/'.$GroupID, pageNumber($Offset, $Limit, true, false)), true));

        $this->setData('Group', $Group);
        $this->setData('Leaders', $this->GroupModel->getLeaders($GroupID));
        $this->setData('Members', $this->GroupModel->getMembers($GroupID,['Role' => GroupModel::ROLE_MEMBER],'', $Limit, $Offset));
        $this->setData('CountMembers', $this->GroupModel->countOfMembers($GroupID,GroupModel::ROLE_MEMBER) );
        $this->setJson('Loading', $Offset.' to '.$Limit);

        // Build a pager
        $PagerFactory = new Gdn_PagerFactory();
        $this->EventArguments['PagerType'] = 'Pager';
        $this->fireEvent('BeforeBuildPager');
        if (!$this->data('_PagerUrl')) {
            $this->setData('_PagerUrl', 'group/members/'.$GroupID.'/{Page}');
        }
        $queryString = '';// DiscussionModel::getSortFilterQueryString($DiscussionModel->getSort(), $DiscussionModel->getFilters());
        $this->setData('_PagerUrl', $this->data('_PagerUrl').$queryString);
        $this->Pager = $PagerFactory->getPager($this->EventArguments['PagerType'], $this);
        $this->Pager->ClientID = 'Pager';
        $this->Pager->configure(
            $Offset,
            $Limit,
            $this->data('CountMembers'),
            $this->data('_PagerUrl')
        );

        PagerModule::current($this->Pager);

        $this->setData('_Page', $Page);
        $this->setData('_Limit', $Limit);

        // Deliver JSON data if necessary
        if ($this->_DeliveryType != DELIVERY_TYPE_ALL) {
            $this->setJson('LessRow', $this->Pager->toString('less'));
            $this->setJson('MoreRow', $this->Pager->toString('more'));
            $this->View = 'members';
        }

        $this->setData('Breadcrumbs', [['Name' => t('Groups'), 'Url' => '/groups'],
            ['Name' => $Group->Name, 'Url' => '/group/'.$GroupID], ['Name' => 'Members']]);

        $this->title(t('Members'));

        $this->render();
    }

    public function removemember($GroupID, $MemberID) {
        if ($this->GroupModel->removeMember($GroupID, $MemberID) === false) {
            $this->Form->addError('Failed to remove a member from this group.');
        }

        $this->View = 'members';
        $this->members($GroupID);
    }

    public function setrole($GroupID, $Role,$MemberID) {
        if(!$this->GroupModel->setRole($GroupID, $MemberID,$Role)) {
            $this->Form->addError('Failed to change a role for the member.');
        }

        $this->View = 'members';
        $this->members($GroupID);
    }

    public function join($GroupID) {
        $Group = $this->GroupModel->getByGroupID($GroupID);
        $this->setData('Group', $Group);
        if ($this->Form->authenticatedPostBack(true)) {
            $result = $this->GroupModel->join($GroupID, Gdn::session()->UserID);
            $this->setRedirectTo('/group/'.$GroupID);
        }
        $this->render();
    }

    public function leave($GroupID) {
        $Group = $this->GroupModel->getByGroupID($GroupID);
        $this->setData('Group', $Group);
        if ($this->Form->authenticatedPostBack(true)) {
            if ($this->GroupModel->removeMember($GroupID, Gdn::session()->UserID) === false) {
                $this->Form->addError('Failed to leave this group.');
            } else {
                $this->setRedirectTo('/groups');
            }
        }
        $this->render();
    }

}
