<?php if (!defined('APPLICATION')) exit();

class VotingPlugin extends Gdn_Plugin {

    /**
     * Add JS & CSS to the page.
     */
    public function AddJsCss($Sender) {
        $Sender->AddCSSFile('voting.css', 'plugins/Voting');
        $Sender->AddJSFile('voting.js', 'plugins/Voting');
    }

    public function addVotingBox($sender, $args) {
        $session = Gdn::Session();
        $object = $args['Object'];
        $VoteType = $args['Type'] == 'Discussion' ? 'votediscussion' : 'votecomment';
        $id = $args['Type'] == 'Discussion' ? val('DiscussionID', $object) : val('CommentID', $object);
        $score = val('Score', $object);
        $cssClass = '';
        $voteUpUrl = '/discussion/'.$VoteType.'/'.$id.'/voteup/'.$session->TransientKey().'/';
        $voteDownUrl = '/discussion/'.$VoteType.'/'.$id.'/votedown/'.$session->TransientKey().'/';
        if (!$session->IsValid()) {
            $voteUpUrl = Gdn::Authenticator()->SignInUrl($sender->SelfUrl);
            $voteDownUrl = $voteUpUrl;
            $cssClass = ' SignInPopup';
        }

        if($args['Type'] == 'Discussion') {
            $discussionModel = new DiscussionModel();
            $currentUserVote = $discussionModel->GetUserScore($id, $session->UserID);
        } else {
            $commentModel = new CommentModel();
            $currentUserVote = $commentModel->GetUserScore($id, $session->UserID);
        }
        $cssClassVoteUp = $cssClassVoteDown = '';
        if($currentUserVote > 0) {
            $cssClassVoteUp = ' Voted';
        } else if($currentUserVote < 0){
            $cssClassVoteDown = ' Voted';
        }

        echo '<span class="Voter">';
        echo Anchor(Wrap('Vote Up', 'span', array('class' => 'ArrowSprite SpriteUp'.$cssClassVoteUp , 'rel' => 'nofollow')), $voteUpUrl, 'VoteUp'.$cssClass);
        echo Wrap(StringIsNullOrEmpty($score) ? '0' : Gdn_Format::BigNumber($score), 'span', array('class' => 'CountVoices'));
        echo Anchor(Wrap('Vote Down', 'span', array('class' => 'ArrowSprite SpriteDown'.$cssClassVoteDown, 'rel' => 'nofollow')), $voteDownUrl, 'VoteDown'.$cssClass);
        echo '</span>&nbsp;|&nbsp;';

    }


    public function discussionController_BeforeInlineDiscussionOptions_handler($sender, $args) {
       $this->addVotingBox($sender, $args);
    }

    public function discussionController_BeforeInlineCommentOptions_handler($sender, $args) {
        $this->addVotingBox($sender, $args);
    }

    public function postController_BeforeInlineCommentOptions_handler($sender, $args) {
        $this->addVotingBox($sender, $args);
    }


    /**
     * Add the files to discussions page
     */
    public function discussionController_render_Before($sender) {
        $this->AddJsCss($sender);
    }


    /**
     * Increment/decrement comment scores
     */
    public function discussionController_VoteComment_create($sender) {
        $CommentID = GetValue(0, $sender->RequestArgs, 0);
        $VoteType = GetValue(1, $sender->RequestArgs);
        $TransientKey = GetValue(2, $sender->RequestArgs);
        $Session = Gdn::Session();
        $FinalVote = 0;
        $Total = 0;
        if ($Session->IsValid() && $Session->ValidateTransientKey($TransientKey) && $CommentID > 0) {
            $CommentModel = new CommentModel();
            $OldUserVote = $CommentModel->GetUserScore($CommentID, $Session->UserID);
            switch ($VoteType) {
                case 'voteup':
                    $NewUserVote = 1;
                    break;
                case 'votedown':
                    $NewUserVote = -1;
                    break;
                default:
                    $NewUserVote  = 0;
            }
            $FinalVote = intval($OldUserVote) + intval($NewUserVote);
            if ($FinalVote == 2 || $FinalVote == -2) {
                // user cancelled a voice
                $FinalVote = 0;
            } else {
                $FinalVote = $NewUserVote;
            }

            $Total = $CommentModel->SetUserScore($CommentID, $Session->UserID, $FinalVote);
        }
        $sender->DeliveryType(DELIVERY_TYPE_BOOL);
        $sender->SetJson('TotalScore', $Total);
        $sender->SetJson('FinalVote', $FinalVote);
        $sender->SetJson('VoteUpCssClass', $FinalVote > 0? 'Voted':'');
        $sender->SetJson('VoteDownCssClass', $FinalVote < 0? 'Voted':'');
        $sender->Render();
    }

    /**
     * Increment/decrement discussion scores
     */
    public function discussionController_VoteDiscussion_create($sender) {
        $DiscussionID = GetValue(0, $sender->RequestArgs, 0);
        $TransientKey = GetValue(1, $sender->RequestArgs);
        $VoteType = FALSE;
        if ($TransientKey == 'voteup' || $TransientKey == 'votedown') {
            $VoteType = $TransientKey;
            $TransientKey = GetValue(2, $sender->RequestArgs);
        }
        $Session = Gdn::Session();
        $NewUserVote = 0;
        $Total = 0;
        if ($Session->IsValid() && $Session->ValidateTransientKey($TransientKey) && $DiscussionID > 0) {
            $DiscussionModel = new DiscussionModel();
            $OldUserVote = $DiscussionModel->GetUserScore($DiscussionID, $Session->UserID);

            switch ($VoteType) {
                case 'voteup':
                    $NewUserVote = 1;
                    break;
                case 'votedown':
                    $NewUserVote = -1;
                    break;
                default:
                    $NewUserVote  = 0;
            }

            $FinalVote = intval($OldUserVote) + intval($NewUserVote);
            if ($FinalVote == 2 || $FinalVote == -2) {
                // user cancelled a voice
                $FinalVote = 0;
            } else {
                $FinalVote = $NewUserVote;
            }
            $Total = $DiscussionModel->SetUserScore($DiscussionID, $Session->UserID, $FinalVote);
        }
        $sender->DeliveryType(DELIVERY_TYPE_BOOL);
        $sender->SetJson('TotalScore', $Total);
        $sender->SetJson('FinalVote', $FinalVote);
        $sender->SetJson('VoteUpCssClass', $FinalVote > 0? 'Voted':'');
        $sender->SetJson('VoteDownCssClass', $FinalVote < 0? 'Voted':'');
        $sender->Render();
    }

    /**
     * Grab the score field whenever the discussions are queried.
     */
    public function DiscussionModel_AfterDiscussionSummaryQuery_Handler($Sender) {
        $Sender->SQL->Select('d.Score');
    }

    /**
     * Add voting css to post controller.
     */
    public function PostController_Render_Before($Sender) {
        $this->AddJsCss($Sender);
    }

    public function Setup() {
    }

    public function OnDisable() {
    }

    public function dashboardNavModule_init_handler($sender)   {
        /** @var DashboardNavModule $nav */
        $nav = $sender;
        $sort = -1;
        $nav->addGroupToSection('Moderation', t('Voting'), 'voting', '', ['after'=>'site'])
            ->addLinkToSectionIf('Garden.Settings.Manage', 'Moderation', t('Discussions'), '/voting/discussions',
                'voting.discussions', '', $sort)
            ->addLinkToSectionIf('Garden.Settings.Manage', 'Moderation', t('Comments'), '/voting/comments',
                'voting.comments', '', $sort);

    }
}