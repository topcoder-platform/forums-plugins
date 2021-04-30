<?php
/**
 * Watching controller
 *
  */

/**
 * Handles displaying watched discussions  and watched categories
 *
  */
class WatchingController extends VanillaController {

    /** @var arrayModels to include. */
    public $Uses = ['Database', 'DiscussionModel', 'Form'];

      /**
     * Highlight route and include JS, CSS, and modules used by all methods.
     *
     * Always called by dispatcher before controller's requested method.
     *
     * @since 2.0.0
     * @access public
     */
    public function initialize() {
        parent::initialize();
        $this->Menu->highlightRoute('/watching');

        /**
         * The default Cache-Control header does not include no-store, which can cause issues (e.g. inaccurate unread
         * status or new comment counts) when users visit the discussion list via the browser's back button.  The same
         * check is performed here as in Gdn_Controller before the Cache-Control header is added, but this value
         * includes the no-store specifier.
         */
        if (Gdn::session()->isValid()) {
            $this->setHeader('Cache-Control', 'private, no-cache, no-store, max-age=0, must-revalidate');
        }

        $this->CountCommentsPerPage = c('Vanilla.Comments.PerPage', 30);
        $this->fireEvent('AfterInitialize');
    }

    /**
     * Display categorioes and discussions the user has watched
     *
     * @param string $cp Category page
     * @param string $dp Discussion page
     * @throws Exception
     */
    public function index($cp = '', $dp = '') {
        $this->addJsFile('jquery.gardenmorepager.js');
        $this->addJsFile('topcoder.js');
        $this->permission('Garden.SignIn.Allow');
        Gdn_Theme::section('CategoryList');

        // Sort filter is used for categories and discussions
        $sort = Gdn::request()->get('sort', null);
        $saveSorting = $sort !== null && Gdn::request()->get('save') && Gdn::session()->validateTransientKey(Gdn::request()->get('TransientKey', ''));
        if($saveSorting) {
            Gdn::session()->setPreference('WatchingSort', $sort);
        }
        $sort =  Gdn::session()->getPreference('WatchingSort', false);
        $this->setData('WatchingSort', $sort);

        $userMetaModel = new UserMetaModel();
        list($cp, $categoryLimit) = offsetLimit($cp, 30);

        // Validate Category Page
        if (!is_numeric($cp) || $cp < 0) {
            $cp = 0;
        }
        $categorySort = $sort == 'old'? 'asc': 'desc';
        $watchedCategoryIDs = $userMetaModel->getWatchedCategories(Gdn::session()->UserID, $categorySort, $categoryLimit, $cp);
        $countOfWatchedCategories =  $userMetaModel->userWatchedCategoriesCount(Gdn::session()->UserID);

        $categories = [];
        $categoryModel  = new CategoryModel();
        foreach ($watchedCategoryIDs as $item) {
           $category =  CategoryModel::categories(val('CategoryID', $item));
            // $category['Archived']
            //  if (!$category['PermsDiscussionsView']) {
            //      continue;
            //  }
            $categories[] = $category;
        }
        $categoryModel->joinRecent($categories);
        $this->setData('WatchedCategories', $categories);
        $this->setData('CountWatchedCategories', $countOfWatchedCategories);

        $pagerFactory = new Gdn_PagerFactory();
        $this->WatchedCategoriesPager = $pagerFactory->getPager('MorePager', $this);
        $this->WatchedCategoriesPager->ClientID='WatchingCategories';
        $this->WatchedCategoriesPager->MoreCode = 'More Categories';
        $this->WatchedCategoriesPager->configure($cp,
            $categoryLimit,
            $countOfWatchedCategories,
            'watching?cp={Page}'
        );

        Gdn_Theme::section('DiscussionList');

        list($dp, $discussionlimit) = offsetLimit($dp, 30);
        if (!is_numeric($dp) || $dp < 0) {
            $dp = 0;
        }

        $discussionModel = new DiscussionModel();
        $discussionModel->setSort($sort);
        $discussionModel->setFilters(Gdn::request()->get());
        $wheres = [
            'w.Bookmarked' => '1',
            'w.UserID' => Gdn::session()->UserID
        ];

        $this->DiscussionData = $discussionModel->get($dp, $discussionlimit, $wheres);
        $this->setData('Discussions', $this->DiscussionData);
        $countDiscussions = $discussionModel->getCount($wheres);
        $this->setData('CountDiscussions', $countDiscussions);

        $pagerFactory = new Gdn_PagerFactory();
        $this->DiscussionPager = $pagerFactory->getPager('MorePager', $this);
        $this->DiscussionPager->ClientID='WatchingDiscussions';
        $this->DiscussionPager->MoreCode = 'More Discussions';
        $this->DiscussionPager->configure($dp,
            $discussionlimit,
            $countDiscussions,
            'watching?dp={Page}');

        $this->allowJSONP(true);

        // Deliver JSON data if necessary
        if ($this->deliveryType() != DELIVERY_TYPE_ALL) {
            if ($dp > 0) {
                //$this->setJson('LessRow', $this->DiscussionPager->toString('less'));
                $this->setJson('MoreRow', $this->DiscussionPager->toString('more'));
                $this->setJson('Loading', $dp.' to '.$discussionlimit);
                $this->View = 'discussions';
           } else if($cp > 0) {
                //$this->setJson('LessRow', $this->WatchedCategoriesPager->toString('less'));
                $this->setJson('MoreRow', $this->WatchedCategoriesPager->toString('more'));
                $this->setJson('Loading', $cp.' to '.$categoryLimit);
                $this->View = 'categories';
            }

        }

       $this->canonicalUrl(url('/watching', true));

        // Add modules
        $this->addModule('DiscussionFilterModule');

        // Render default view
        $this->setData('Title', t('Watching'));
        $this->setData('Breadcrumbs', [['Name' => t('Watching'), 'Url' => '/watching']]);

        $this->render();
    }
}
