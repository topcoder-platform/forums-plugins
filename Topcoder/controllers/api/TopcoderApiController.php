<?php

use Garden\Web\Exception\ClientException;

/**
 * Topcoder API Controller for the `/topcoder` resource.
 */
class TopcoderApiController extends AbstractApiController{

    /** @var UserMetaModel */
    private $userMetaModel;
    /** @var UserMetaModel */
    private $categoryModel;
    /**
     * TopcoderApiController constructor.
     *
     * @param UserMetaModel $userMetaModel
     * @param CategoryModel $categoryModel
     */
    public function __construct(UserMetaModel $userMetaModel, CategoryModel $categoryModel) {
        $this->userMetaModel = $userMetaModel;
        $this->categoryModel = $categoryModel;
    }

    /**
     * Lookup a single category by its numeric ID
     *
     * @param int $id The category ID
     * @throws NotFoundException if the category cannot be found.
     * @return array
     */
    private function category($id) {
        $category = CategoryModel::categories($id);
        if (empty($category)) {
            throw new NotFoundException('Category');
        }
        return $category;
    }

    /**
     * Add the "watch" status on a category for the user.
     *
     * @param int $id The target category's ID.
     * @param $userId The target user's ID.
     * @param array $body
     * @return array
     * @throws ClientException
     * @throws \Garden\Schema\ValidationException
     * @throws \Garden\Web\Exception\HttpException
     * @throws \Vanilla\Exception\PermissionException
     */
    public function put_watch($userId,$id, array $body) {
        $this->permission('Garden.SignIn.Allow');
        $schema = ['watched:b' => 'The category-watched status for the user.'];
        $in = $this->schema($schema, 'in');
        $out = $this->schema($schema, 'out');
        $body = $in->validate($body);
        $newEmailCommentKey = 'Preferences.Email.NewComment.'.$id;
        $newEmailDiscussionKey = 'Preferences.Email.NewDiscussion.'.$id;
        $newPopupCommentKey = 'Preferences.Popup.NewComment.'.$id;
        $newPopupDiscussionKey = 'Preferences.Popup.NewDiscussion.'.$id;
        $isDiscussionFollowed = count($this->userMetaModel->getUserMeta($userId,$newEmailDiscussionKey)) > 0;

        // Is this a new watch?
        if ($body['watched'] && !$isDiscussionFollowed) {
            $category = $this->category($id);
            $this->permission('Vanilla.Discussions.View', $category['PermissionCategoryID']);
        }
        // null is used to remove data
        $watched = $body['watched'] ? 1 : null;
        $this->userMetaModel->setUserMeta($userId, $newEmailCommentKey , $watched);
        $this->userMetaModel->setUserMeta($userId, $newEmailDiscussionKey, $watched);
        $this->userMetaModel->setUserMeta($userId, $newPopupCommentKey , $watched);
        $this->userMetaModel->setUserMeta($userId, $newPopupDiscussionKey , $watched);

        $result = $out->validate([
            'watched' => count($this->userMetaModel->getUserMeta($userId,$newEmailDiscussionKey)) > 0
        ]);
        return $result;
    }

    /**
     * List of Topcoder Users
     * Search members by handle
     *
     * @param array $query The query string.
     * @return Data
     */
    public function index(array $query) {
        $this->permission();
        $token = TopcoderPlugin::getM2MToken();
        $in = $this->schema([
            'handle:s?' => [
                'description' => 'Filter by Topcoder handle.',
                'x-filter' => [
                    'field' => 'handle'
                ],
            ]
        ])->setDescription('List of Topcoder users.');
        $query = $in->validate($query);
        $handle = $query['handle'];
        $options = array('http' => array(
            'method' => 'GET',
            'header' => 'Authorization: Bearer ' .$token
        ));
        $context = stream_context_create($options);
        $topcoderMembersApiUrl = c('Plugins.Topcoder.BaseApiURL').'/v5/members/autocomplete?term='.$handle;
        $memberData = @file_get_contents($topcoderMembersApiUrl, false, $context);
        if($memberData === false) {
            // Handle errors (e.g. 404 and others)
            return [];
        }
        $memberResponse = json_decode($memberData);
        return  $memberResponse;
    }

}