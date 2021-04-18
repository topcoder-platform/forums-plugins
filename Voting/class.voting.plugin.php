<?php if (!defined('APPLICATION')) exit();

class VotingPlugin extends Gdn_Plugin {

    /**
     * Database updates.
     */
    public function structure() {
        include __DIR__.'/structure.php';
    }
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
        $pScore = val('PScore', $object);
        $nScore = val('NScore', $object);
        $cssClass = '';
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

        $control = generateVoterBox($id,$args['Type'], $pScore, $nScore,  $currentUserVote );

        if ($session->IsValid()) {
            $control .='<span class="line"></span>';
        }
        echo $control;

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
     * Sets the discussion score for specified user.
     *
     * @param int $discussionID Unique ID of discussion to update.
     * @param int $userID Unique ID of user setting score.
     * @param int $score New score for discussion.
     * @return int Total score.
     */
    public function discussionModel_setUserScores_create($sender) {
        $discussionID = val(0, $sender->EventArguments);
        $userID = val(1, $sender->EventArguments);
        $score = val(2, $sender->EventArguments);
        $prevScore = val(3, $sender->EventArguments);


        // Insert or update the UserDiscussion row
        $sender->SQL->replace(
            'UserDiscussion',
            ['Score' => $score],
            ['DiscussionID' => $discussionID, 'UserID' => $userID]
        );

        // Get the current total score
        $totalScore = $sender->SQL->select('Score', 'sum', 'TotalScore')
            ->select('NScore', 'sum', 'TotalNScore')
            ->select('PScore', 'sum', 'TotalPScore')
            ->from('Discussion')
            ->where('DiscussionID', $discussionID)
            ->get()
            ->firstRow();

        $pScore = 0;
        $nScore = 0;
        if($totalScore) {
            $pScore = $totalScore->TotalPScore? $totalScore->TotalPScore : 0;
            $nScore = $totalScore->TotalNScore? $totalScore->TotalNScore: 0;
        }
        if ($prevScore == null) {
            $pScore = $score > 0? $pScore+1 : $pScore;
            $nScore = $score < 0? $nScore+1 : $nScore;
            $tScore = $pScore+$nScore;
        } else {
            if ($score == 0) { // cancelled a vote
                $pScore = $prevScore > 0 ? $pScore - 1 : $pScore;
                $nScore = $prevScore < 0 ? $nScore - 1 : $nScore;
                $tScore = $pScore + $nScore;
            } else { //change a vote
                $pScore = $pScore + $score ;
                $nScore = $nScore + (-1)*$score;
                $tScore = $pScore + $nScore;
            }
        }

        // Update the Discussion's cached version
        $sender->SQL->update('Discussion')
            ->set('Score', $tScore)
            ->set('PScore', $pScore )
            ->set('NScore', $nScore)
            ->where('DiscussionID', $discussionID)
            ->put();

        $updatedTotalScores = $sender->SQL->select('Score', 'sum', 'TotalScore')
            ->select('NScore', 'sum', 'TotalNScore')
            ->select('PScore', 'sum', 'TotalPScore')
            ->from('Discussion')
            ->where('DiscussionID', $discussionID)
            ->get()
            ->firstRow();
        return $updatedTotalScores;
    }

    /**
     * Upadte Comment Score value for the specified user and update Total Comment Scores
     *
     * @param int $commentID Unique ID of comment we're getting the score for.
     * @param int $userID Unique ID of user who scored the comment.
     */
    public function commentModel_setUserScores_create($sender) {

        $commentID = val(0, $sender->EventArguments);
        $userID = val(1, $sender->EventArguments);
        $score = val(2, $sender->EventArguments);
        $prevScore = val(3, $sender->EventArguments);

        // Insert or update the UserComment row
        $sender->SQL->replace(
            'UserComment',
            ['Score' => $score],
            ['CommentID' => $commentID, 'UserID' => $userID]
        );

        $totalScore = $sender->SQL->select('Score', 'sum', 'TotalScore')
            ->select('NScore', 'sum', 'TotalNScore')
            ->select('PScore', 'sum', 'TotalPScore')
            ->from('Comment')
            ->where('CommentID', $commentID)
            ->get()
            ->firstRow();

        $pScore = 0;
        $nScore = 0;

        if($totalScore) {
            $pScore = $totalScore->TotalPScore? $totalScore->TotalPScore : 0;
            $nScore = $totalScore->TotalNScore? $totalScore->TotalNScore: 0;
        }
        if ($prevScore == null) {
            $pScore = $score > 0? $pScore+1 : $pScore;
            $nScore = $score < 0? $nScore+1 : $nScore;
            $tScore = $pScore+$nScore;
        } else {
            if ($score == 0) { // cancelled a vote
                $pScore = $prevScore > 0 ? $pScore - 1 : $pScore;
                $nScore = $prevScore < 0 ? $nScore - 1 : $nScore;
                $tScore = $pScore + $nScore;
            } else { //change a vote
                $pScore = $pScore + $score ;
                $nScore = $nScore + (-1)*$score;
                $tScore = $pScore + $nScore;
            }
        }

        // Update the comment's cached version
        $sender->SQL->update('Comment')
            ->set('Score', $tScore)
            ->set('PScore', $pScore )
            ->set('NScore', $nScore)
            ->where('CommentID', $commentID)
            ->put();

        $updatedTotalScores = $sender->SQL->select('Score', 'sum', 'TotalScore')
            ->select('NScore', 'sum', 'TotalNScore')
            ->select('PScore', 'sum', 'TotalPScore')
            ->from('Comment')
            ->where('CommentID', $commentID)
            ->get()
            ->firstRow();
        return $updatedTotalScores;
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
        }

        $Total = $CommentModel->SetUserScores($CommentID, $Session->UserID, $FinalVote, $OldUserVote);
        $sender->DeliveryType(DELIVERY_TYPE_VIEW);
        $voterBoxID = '#Voter_Comment_'.$CommentID;
        $pScore = val('TotalPScore', $Total);
        $nScore = val('TotalNScore', $Total);
        $html = generateVoterBox($CommentID,'Comment', $pScore, $nScore, $FinalVote);
        $sender->jsonTarget($voterBoxID, $html, 'ReplaceWith');
        $sender->render('Blank', 'Utility', 'Dashboard');
    }

    /**
     * Increment/decrement discussion scores
     */
    public function discussionController_VoteDiscussion_create($sender) {
        $DiscussionID = GetValue(0, $sender->RequestArgs, 0);
        $VoteType = GetValue(1, $sender->RequestArgs);
        $TransientKey = GetValue(2, $sender->RequestArgs);
        $Session = Gdn::Session();
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
            $Total = $DiscussionModel->SetUserScores($DiscussionID, $Session->UserID, $FinalVote,$OldUserVote);
            $sender->DeliveryType(DELIVERY_TYPE_VIEW);
            $voterBoxID = '#Voter_Discussion_'.$DiscussionID;
            $pScore = val('TotalPScore', $Total);
            $nScore = val('TotalNScore', $Total);
            $html = generateVoterBox($DiscussionID,'Discussion', $pScore, $nScore, $FinalVote);
            $sender->jsonTarget($voterBoxID, $html, 'ReplaceWith');
            $sender->render('Blank', 'Utility', 'Dashboard');
        }
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
        $this->structure();
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

if (!function_exists('formattedNScore')) {
   function formattedNScore($score)
    {
        if (StringIsNullOrEmpty($score)) {
            $formattedScore = '-0';
        } else {
            $formattedScore = '-' . Gdn_Format::BigNumber($score);
        }

        return $formattedScore;
    }
}

if (!function_exists('formattedPScore')) {
    function formattedPScore($score)
    {
        if (StringIsNullOrEmpty($score)) {
            $formattedScore = '+0';
        } else {
            $formattedScore = '+' . Gdn_Format::BigNumber($score);
        }

        return $formattedScore;
    }
}

if (!function_exists('generateVoterBox')) {
    function generateVoterBox($id, $VoteType, $pScore, $nScore, $currentUserVote) {

        $cssClassVoteUp = 'SpriteVoteUp';
        $cssClassVoteDown = 'SpriteVoteDown';
        if($currentUserVote > 0) {
            $cssClassVoteUp = 'SpriteVoteUpActive';
        } else if($currentUserVote < 0){
            $cssClassVoteDown = 'SpriteVoteDownActive';
        }

        $voterBoxID = 'Voter_' . $VoteType . '_' . $id;
        $voteUpUrl = '/discussion/vote' . strtolower($VoteType) . '/' . $id . '/voteup/' . Gdn::session()->TransientKey() . '/';
        $voteDownUrl = '/discussion/vote' . strtolower($VoteType) . '/' . $id . '/votedown/' . Gdn::session()->TransientKey() . '/';

        if (!Gdn::session()->IsValid()) {
            $voteUpUrl = Gdn::Authenticator()->SignInUrl(Gdn::controller()->SelfUrl);
            $voteDownUrl = Gdn::Authenticator()->SignInUrl(Gdn::controller()->SelfUrl);
        }

        $result = '<span id="' . $voterBoxID . '" class="Voter">';
        // The up/down vote buttons are clickable in guest mode
        if(Gdn::session()->isValid()) {
            $result .= Anchor(Wrap('', 'span', array('class' => 'icon ' . $cssClassVoteUp, 'rel' => 'nofollow')), $voteUpUrl, 'VoteUp');
        } else {
            $result .= Wrap(Wrap('', 'span', array('class' => 'icon ' . $cssClassVoteUp, 'rel' => 'nofollow')), 'span', array('class' =>'VoteUp'));
        }

        $counts = formattedPScore($pScore);
        if(!StringIsNullOrEmpty($nScore) && $nScore != 0) {
            $counts .= '<span class="VoiceDivider">/</span>' . formattedNScore($nScore);
        }
        $result .= Wrap($counts, 'span', array('class' => 'CountVoices'));
        if(Gdn::session()->isValid()) {
            $result .= Anchor(Wrap('', 'span', array('class' => 'icon ' . $cssClassVoteDown, 'rel' => 'nofollow')), $voteDownUrl, 'VoteDown');
        } else {
            $result .= Wrap(Wrap('', 'span', array('class' => 'icon ' . $cssClassVoteDown, 'rel' => 'nofollow')), 'span', array('class' =>'VoteDown'));
        }
        $result .= '</span>';

        return $result;
    }
}