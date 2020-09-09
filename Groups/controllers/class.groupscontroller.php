<?php
/**
 * Groups controller
 */

use Vanilla\Message;

/**
 * Handles accessing & displaying a single group via /groups endpoint.
 */
class GroupsController extends VanillaController {

    /** @var array Models to include. */
    public $Uses = ['Form', 'Database', 'GroupModel'];


    public function __construct() {
        parent::__construct();
    }

    public function initialize() {
        parent::initialize();
        $this->Menu->highlightRoute('/groups');
        /**
         * The default Cache-Control header does not include no-store, which can cause issues (e.g. inaccurate unread
         * status or new comment counts) when users visit the discussion list via the browser's back button.  The same
         * check is performed here as in Gdn_Controller before the Cache-Control header is added, but this value
         * includes the no-store specifier.
         */
        if (Gdn::session()->isValid()) {
            $this->setHeader('Cache-Control', 'private, no-cache, no-store, max-age=0, must-revalidate');
        }

        $this->fireEvent('AfterInitialize');
    }

    public function index($Page = false) {
        // Setup head
        $this->allowJSONP(true);
        Gdn_Theme::section('GroupList');

        // Determine offset from $Page
        list($Offset, $Limit) = offsetLimit($Page, c('Vanilla.Groups.PerPage', 30), true);
        $Page = pageNumber($Offset, $Limit);

        // Allow page manipulation
        $this->EventArguments['Page'] = &$Page;
        $this->EventArguments['Offset'] = &$Offset;
        $this->EventArguments['Limit'] = &$Limit;
        $this->fireEvent('AfterPageCalculation');

        // Set canonical URL
        $this->canonicalUrl(url(concatSep('/', 'groups', pageNumber($Offset, $Limit, true, false)), true));

        $this->title(t('Groups'));
        $this->setData('Breadcrumbs', [['Name' => t('Groups'), 'Url' => '/groups']]);

        $GroupModel = new GroupModel();

        $where = false;
        $this->GroupData = $GroupModel->getWhere(false, '', 'asc', $Limit, $Offset);

        $CountGroups = $GroupModel->getCount($where);
        $this->setData('CountGroups', $CountGroups);
        $this->setData('Groups', $this->GroupData, true);
        $this->setData('CurrentUserGroups', $GroupModel->memberOf(Gdn::session()->UserID));
        $this->setJson('Loading', $Offset.' to '.$Limit);

        // Build a pager
        $PagerFactory = new Gdn_PagerFactory();
        $this->EventArguments['PagerType'] = 'Pager';
        $this->fireEvent('BeforeBuildPager');
        if (!$this->data('_PagerUrl')) {
            $this->setData('_PagerUrl', 'groups/{Page}');
        }
        $queryString = '';// DiscussionModel::getSortFilterQueryString($DiscussionModel->getSort(), $DiscussionModel->getFilters());
        $this->setData('_PagerUrl', $this->data('_PagerUrl').$queryString);
        $this->Pager = $PagerFactory->getPager($this->EventArguments['PagerType'], $this);
        $this->Pager->ClientID = 'Pager';
        $this->Pager->configure(
            $Offset,
            $Limit,
            $this->data('CountGroups'),
            $this->data('_PagerUrl')
        );

        PagerModule::current($this->Pager);

        $this->setData('_Page', $Page);
        $this->setData('_Limit', $Limit);
        $this->fireEvent('AfterBuildPager');

        // Deliver JSON data if necessary
        if ($this->_DeliveryType != DELIVERY_TYPE_ALL) {
            $this->setJson('LessRow', $this->Pager->toString('less'));
            $this->setJson('MoreRow', $this->Pager->toString('more'));
            $this->View = 'groups';
        }

        $this->render();
    }
}
