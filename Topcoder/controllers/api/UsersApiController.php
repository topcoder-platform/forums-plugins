<?php

use Garden\Schema\Schema;
use Garden\Schema\ValidationException;
use Garden\Schema\ValidationField;
use Garden\Web\Exception\ClientException;
use Garden\Web\Exception\NotFoundException;
use Vanilla\ApiUtils;

/**
 * Users API Controller for the `/users` resource.
 */
class UsersApiController extends AbstractApiController{

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


    public function get_mePreferences() {
        $this->permission('Garden.SignIn.Allow');
        $user = Gdn::userModel()->getID(Gdn::session()->UserID, DATASET_TYPE_ARRAY);
        $preferences = $this->userMetaModel->getUserMeta($user['UserID'], 'Preferences.%', 'Preferences.');

        $metaKeyCategories = [];
        foreach ($preferences as $metaKey =>$value) {
            $items = explode('.', $metaKey);
            $key = $items[1].'.'.$items[2];
            $categoryID = (int) $items[3];
            $metaKeyCategories[$categoryID][$key] = (int)$value;
        }

        $categories = [];
        foreach ($metaKeyCategories as $categoryID =>$value) {
            array_push($categories , array_merge(['CategoryID' => $categoryID],  $value));

        }
        // Default Vanilla Settings
        $userPreferences = [
            'GeneralPreferences' =>  [
                'Email.DiscussionComment' => (int) val('Email.DiscussionComment', $user['Preferences'], c('Preferences.Email.DiscussionComment')),
                'Email.BookmarkComment' => (int) val('Email.BookmarkComment', $user['Preferences'], c('Preferences.Email.BookmarkComment')),
                'Email.Mention' => (int) val('Email.Mention', $user['Preferences'], c('Preferences.Email.Mention')),
                'Email.ParticipateComment' => (int) val('Email.ParticipateComment', $user['Preferences'], c('Preferences.Email.ParticipateComment')),
                'Popup.DiscussionComment' => (int) val('Popup.DiscussionComment', $user['Preferences'], c('Preferences.Popup.DiscussionComment')),
                'Popup.BookmarkComment' => (int) val('Popup.BookmarkComment', $user['Preferences'], c('Preferences.Popup.BookmarkComment')),
                'Popup.Mention' => (int) val('Popup.Mention', $user['Preferences'], c('Preferences.Popup.Mention')),
                'Popup.ParticipateComment' => (int) val('Popup.ParticipateComment', $user['Preferences'], c('Preferences.Popup.ParticipateComment'))],
            'CategoryPreferences' =>  $categories
        ];

        return $userPreferences;
    }

    public function patch_mePreferences(array $body) {

        $this->permission('Garden.SignIn.Allow');
        $in = $this->schema($this->notificationPreferencesPatchSchema(), 'in')
            ->setDescription('Update User Notification Preferences.');
        $body = $in->validate($body);
        $generalPreferences = $body['GeneralPreferences'];

        $preferences = [];
        if(isset($generalPreferences['Email.DiscussionComment'])){
            $preferences['Email.DiscussionComment'] = (int)$generalPreferences['Email.DiscussionComment'];
        }
        if(isset($generalPreferences['Email.BookmarkComment'])){
            $preferences['Email.BookmarkComment'] = (int)$generalPreferences['Email.BookmarkComment'];
        }

        if(isset($generalPreferences['Email.Mention'])){
            $preferences['Email.Mention'] = (int)$generalPreferences['Email.Mention'];
        }

        if(isset($generalPreferences['Email.ParticipateComment'])){
            $preferences['Email.ParticipateComment'] = (int)$generalPreferences['Email.ParticipateComment'];
        }

        if(isset($generalPreferences['Popup.DiscussionComment'])){
            $preferences['Popup.DiscussionComment'] = (int) $generalPreferences['Popup.DiscussionComment'];
        }
        if(isset($generalPreferences['Popup.BookmarkComment'])){
            $preferences['Popup.BookmarkComment'] = (int) $generalPreferences['Popup.BookmarkComment'];
        }

        if(isset($generalPreferences['Popup.Mention'])){
            $preferences['Popup.Mention'] = (int)$generalPreferences['Popup.Mention'];
        }

        if(isset($generalPreferences['Popup.ParticipateComment'])){
            $preferences['Popup.ParticipateComment'] = (int)$generalPreferences['Popup.ParticipateComment'];
        }

        if(count($preferences) > 0 ) {
            Gdn::userModel()->savePreference(Gdn::session()->UserID, $generalPreferences);
        }

        if(isset($body['CategoryPreferences'])){
            $metaData = [];
            foreach ($body['CategoryPreferences'] as $entity) {
                $categoryID= val('CategoryID', $entity);
                $category = CategoryModel::categories($categoryID);
                if (empty($category)) {
                    throw new NotFoundException('Category');
                }

               if (!CategoryModel::checkPermission($categoryID,'Vanilla.Discussions.View', true)) {
                    $this->permission('Vanilla.Discussions.View', true, 'Category', $categoryID);
               }
               if(isset($entity['Email.NewDiscussion'])) {
                   $metaKey = 'Preferences.Email.NewDiscussion.'.$categoryID;
                   $metaData[$metaKey] =(int)$entity['Email.NewDiscussion'];
               }

               if(isset($entity['Email.NewComment'])) {
                   $metaKey = 'Preferences.Email.NewComment.'.$categoryID;
                   $metaData[$metaKey] = (int)$entity['Email.NewComment'];
               }

               if(isset($entity['Popup.NewDiscussion'])) {
                   $metaKey = 'Preferences.Popup.NewDiscussion.'.$categoryID;
                   $metaData[$metaKey] = (int)$entity['Popup.NewDiscussion'];
               }

                if(isset($entity['Popup.NewComment'])) {
                    $metaKey = 'Preferences.Popup.NewComment.'.$categoryID;
                    $metaData[$metaKey] =(int)$entity['Popup.NewComment'];
                }
            }

            foreach ( $metaData as $key =>$value) {
                $this->userMetaModel->setUserMeta(Gdn::session()->UserID, $key, $value > 0?$value: null);
            }
        }

        return $this->get_mePreferences();
    }

    protected function notificationPreferencesPatchSchema() {
        $schema = [
            'GeneralPreferences?'=> [
                'type' => 'object',
                'properties' => [
                    'Email.DiscussionComment:i' => [
                        'minimum' => 0,
                        'maximum' => 1,
                        'description' => 'Notify me when people comment on my discussions',
                    ],
                    'Email.BookmarkComment:i' => [
                        'minimum' => 0,
                        'maximum' => 1,
                        'description' => 'Notify me when people comment on my bookmarked discussions'
                    ],
                    'Email.Mention:i' => [
                        'minimum' => 0,
                        'maximum' => 1,
                        'description' => 'Notify me when people mention me'
                    ],
                    'Email.ParticipateComment:i' => [
                        'minimum' => 0,
                        'maximum' => 1,
                        'description' => 'Notify me when people comment on discussions I\'ve participated in'
                    ],
                    'Popup.DiscussionComment:i' => [
                        'minimum' => 0,
                        'maximum' => 1,
                        'description' => 'Notify me when people comment on my discussions',
                    ],
                    'Popup.BookmarkComment:i' => [
                        'minimum' => 0,
                        'maximum' => 1,
                        'description' => 'Notify me when people comment on my bookmarked discussions'
                    ],
                    'Popup.Mention:i' => [
                        'minimum' => 0,
                        'maximum' => 1,
                        'description' => 'Notify me when people mention me'
                    ],
                    'Popup.ParticipateComment:i' => [
                        'minimum' => 0,
                        'maximum' => 1,
                        'description' => 'Notify me when people comment on discussions I\'ve participated in'
                    ],
                    ]
            ],
            'CategoryPreferences?' => [
                'type' => 'array',
                'items' => [
                    'type' => 'object',
                    'properties' => [
                        'CategoryID' => [
                        'type' => 'integer',
                        'minimum' => 1,
                         ],
                        'Email.NewDiscussion' => [
                            'type' => 'integer',
                            'minimum' => 0,
                            'maximum' => 2,
                        ],
                        'Email.NewComment' => [
                            'type' => 'integer',
                            'minimum' => 0,
                            'maximum' => 2,
                        ],
                        'Popup.NewDiscussion' => [
                            'type' => 'integer',
                            'minimum' => 0,
                            'maximum' => 2,
                        ],
                        'Popup.NewComment' => [
                            'type' => 'integer',
                            'minimum' => 0,
                            'maximum' => 2,
                        ]
                    ]
                ]
            ]
        ];
        return $schema;
    }

}