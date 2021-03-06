<?php
/**
 * View Voting Discussions/Comments
 *
 * @copyright 2009-2019 Vanilla Forums Inc.
 * @license GPL-2.0-only
 * @package Dashboard
 * @since 2.0
 */

use Vanilla\Contracts\ConfigurationInterface;

/**
 * Handles /voting endpoint.
 */
class VotingController extends DashboardController {

    /** @var ConfigurationInterface */
    private $config;

    /** @var array Models to automatically instantiate. */
    public $Uses = ['Database', 'Form'];

    /** @var Gdn_Form */
    public $Form;

    public $discussionModel;

    /**
     * Configure the controller.
     */
    public function __construct(ConfigurationInterface $config = null) {
        $this->config = $config instanceof ConfigurationInterface ? $config : Gdn::getContainer()->get(ConfigurationInterface::class);
        $this->discussionModel = Gdn::getContainer()->get(DiscussionModel::class);
        parent::__construct();
    }

    /**
     * Highlight menu path. Automatically run on every use.
     */
    public function initialize() {
        parent::initialize();
        Gdn_Theme::section('Dashboard');
        if ($this->Menu) {
            $this->Menu->highlightRoute('/dashboard/settings');
        }
        $this->fireEvent('Init');
    }

    /**
     * Discussion list.
     * @param string $page Page number.
     * @param string $sort
     * @throws Exception
     */
    public function discussions($page = '', $sort = 'totalvotes') {
        $this->permission('Garden.Settings.Manage');

        // Page setup
        $this->addJsFile('jquery.gardenmorepager.js');
        $this->title(t('Voting Discussions'));
        $this->setHighlightRoute('voting/discussions');
        Gdn_Theme::section('Moderation');

        // Input Validation.
        list($offset, $limit) = offsetLimit($page, PagerModule::$DefaultPageSize);

        $DiscussionModel = new DiscussionModel();
        switch (strtolower($sort)) {
            case 'totalvotes':
               // $orderBy = ['d.Score'=> 'desc', 'd.PScore'=>' desc', 'd.NScore'=> 'desc'];
                $orderBy = 'd.Score';
                break;
            case 'votesup':
                $orderBy = 'd.PScore';
                break;
            case 'votesdown':
                $orderBy = 'd.NScore';
                break;
            case 'comments':
                $orderBy = 'd.CountComments';
                break;
            default:
                $orderBy = 'd.Score';
        }

        // TODO
        // , 'd.Score is not null' => ''
        $where = ['Announce' => 'all', 'd.Score is not null' => ''];
        // Get Discussion Count
        $CountDiscussions = $DiscussionModel->getCount($where);

        $this->setData('RecordCount', $CountDiscussions);

        // Get Discussions  and Announcements
        //$discussionData = $DiscussionModel->getWhereRecent($where, $limit, $offset);
        $discussionData = $DiscussionModel->getWhere($where, $orderBy, 'desc', $limit, $offset);
        $this->setData('Discussions', $discussionData);

        // Deliver json data if necessary
        if ($this->_DeliveryType != DELIVERY_TYPE_ALL && $this->_DeliveryMethod == DELIVERY_METHOD_XHTML) {
            $this->setJson('LessRow', $this->Pager->toString('less'));
            $this->setJson('MoreRow', $this->Pager->toString('more'));
            $this->View = 'discussions';
        }

        $this->render();
    }

    /**
     * Comment list.
     * @param string $page Page number.
     * @param string $sort
     * @throws Exception
     */
    public function comments($page = '', $sort = 'totalvotes') {
        $this->permission('Garden.Settings.Manage');

        // Page setup
        $this->addJsFile('jquery.gardenmorepager.js');
        $this->title(t('Voting Comments'));
        $this->setHighlightRoute('voting/comments');
        Gdn_Theme::section('Moderation');

        // Input Validation.
        list($offset, $limit) = offsetLimit($page, PagerModule::$DefaultPageSize);

        $CommentModel = new CommentModel();

        switch (strtolower($sort)) {
            case 'totalvotes':
                $CommentModel->OrderBy(array('c.Score desc', 'c.PScore desc', 'c.NScore desc'));
                break;
            case 'votesup':
                $CommentModel->OrderBy(array('c.PScore desc', 'c.Score desc', 'c.NScore desc'));
                break;
            case 'votesdown':
                $CommentModel->OrderBy(array('c.NScore desc', 'c.Score desc', 'c.PScore desc'));
                break;
            default:
                $CommentModel->OrderBy(array('c.Score desc', 'c.PScore desc', 'c.NScore desc'));
                break;
        }

        $where = ['Score is not null' => ''];
        // Get Comment Count
        $CountComments = $CommentModel->getCount($where);
        $this->setData('RecordCount', $CountComments);

        $data = $CommentModel->getWhere($where,'', '' , $limit, $offset);
        $this->setData('Comments', $data);

        // Deliver json data if necessary
        if ($this->_DeliveryType != DELIVERY_TYPE_ALL && $this->_DeliveryMethod == DELIVERY_METHOD_XHTML) {
            $this->setJson('LessRow', $this->Pager->toString('less'));
            $this->setJson('MoreRow', $this->Pager->toString('more'));
            $this->View = 'discussions';
        }

        $this->render();
    }


    /**
     * Build URL to order users by value passed.
     */
    protected function _OrderDiscussionsUrl($field) {
        $get = Gdn::request()->get();
        $get['sort'] = $field;
        $get['Page'] = 'p1';
        return '/voting/discussions?'.http_build_query($get);
    }

    /**
     * Build URL to order users by value passed.
     */
    protected function _OrderCommentsUrl($field) {
        $get = Gdn::request()->get();
        $get['sort'] = $field;
        $get['Page'] = 'p1';
        return '/voting/comments?'.http_build_query($get);
    }


}
