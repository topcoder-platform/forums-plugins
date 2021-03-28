<?php

/**
 * Class ReplyToModel
 */
class ReplyToModel extends Gdn_Model {

    /**
     * Return the number of comments on a discussion.
     * Used to check whether left/right numbers need refreshing.
     * @param $DiscussionID
     * @return false|Gdn_Dataset|int|object
     */
    public function commentCount($DiscussionID) {
        $m = new CommentModel();
        return $m->GetCount($DiscussionID);
    }

    /**
     * Get the highest 'right' value in a set of discussion comments.
     *
     * @param $DiscussionID
     * @return int
     */
    public function maxRight($DiscussionID) {
        $SQL = Gdn::SQL();
        $MaxRight = $SQL->Select('TreeRight', 'max', 'MaxRight')
            ->From('Comment')
            ->Where('DiscussionID', $DiscussionID)
            ->Get()
            ->FirstRow()
            ->MaxRight;

        return (!empty($MaxRight) ? $MaxRight : 0);
    }

    /**
     * Rebuild the left/right values for a discussion.
     * We are effectively creating a nested sets model from a simple adjacency model.
     * There are ways of doing this using temporary tables, but we will use PHP arrays
     * To build the tree before using it to update the discussion comments.
     * @param $ParentID
     * @param null $reset_parents
     * @param null $reset_index
     * @return array|mixed
     */
    public function treeWalk($ParentID, $reset_parents = NULL, $reset_index = NULL) {
        static $index = 1;
        static $parents = array();

        $return = array();

        if (isset($reset_index)) {
            $index = $reset_index;
        }

        if (isset($reset_parents)) {
            $parents = $reset_parents;
        }

        foreach ($parents[$ParentID] as $parent) {
            $return[$parent] = array();

            $index += 1;
            $left = $index;

            // Sub-comments
            if (isset($parents[$parent])) {
                $sub = $this->treeWalk($parent);
            } else {
                $sub = array();
            }

            $index += 1;
            $right = $index;

            $return[$parent] = array('left' => $left, 'right' => $right);

            if (!empty($sub)) $return = $return + $sub;
        }

        // Consume the parent list now we have added it to the result.
        unset($parents[$ParentID]);

        // If this is the outer loop and we still have unconsumed parent lists, then tag them onto the end.
        // We want to make sure every comment in the discussion gets added to the tree somewhere.
        if (isset($reset_parents) && !empty($parents)) {
            while (!empty($parents)) {
                $next_parent_id = reset(array_keys($parents));
                $return = $return + $this->treeWalk($next_parent_id);
            }
        }

        return $return;
    }

    public function rebuildLeftRight($DiscussionID) {
        // Get all the comments for the discussion.
        // Order by parent and then creation date.
        $SQL = Gdn::SQL();

        $Data = $SQL->Select('CommentID')->Select('ParentCommentID')
            ->From('Comment')
            ->Where('DiscussionID', $DiscussionID)
            ->OrderBy('ParentCommentID', 'asc')
            ->OrderBy('DateInserted', 'asc')
            ->Get();

        $parents = array();

        while ($Row = $Data->NextRow()) {
            if (empty($parents[$Row->ParentCommentID])) $parents[$Row->ParentCommentID] = array();
            $parents[$Row->ParentCommentID][] = $Row->CommentID;
        }

        // Now we have the comments, grouped into parents.
        // Turn it into a tree.
        // Keys are the comment IDs, and values are the comment IDs or an array of sub-comments.
        $tree = $this->treeWalk(0, $parents, 0);

        // Now use this tree to update the left/right values of the comments.
        $LeftData = array();
        $RightData = array();

        foreach ($tree as $key => $value) {
            $LeftData[$key] = $value['left'];
            $RightData[$key] = $value['right'];
        }

        $LeftData[''] = 'TreeLeft';
        $RightData[''] = 'TreeRight';
        $Update = $SQL->Update('Comment')
            ->Set('TreeLeft', $this->setCase('TreeLeft', 'CommentID', $LeftData), FALSE)
            ->Set('TreeRight', $this->setCase('TreeRight', 'CommentID', $RightData), FALSE)
            ->Where('DiscussionID', $DiscussionID)
            ->Put();

    }

    /**
    * Create a "case A when B then C [when D then E ...] [else F];" sql fragment
    * to be used with "SET" statement. "A" is $Field and $Options define the
    * remainder in the same format as the $GDN::SQL()->SelectCase() method.
    * Returns a string.
    * Note no escaping or quoting is done here, so only use with numeric values for now.
    */
    public function setCase($SetField, $Field, $Options) {
        $CaseOptions = 'case ' . $Field;

        if (empty($Options)) {
            // For some reason there are no options, so just return the field we are updating.
            return $SetField;
        } else {
            foreach ($Options as $Key => $Val) {
                if ($Key == '') {
                    $Default = $Val;
                } else {
                    $CaseOptions .= ' when ' . $Key . ' then ' . $Val;
                }
            }
        }

        if (isset($Default)) $CaseOptions .= ' else ' . $Default;

        $CaseOptions .= ' end';

        return $CaseOptions;
    }

    /**
     * Get the tree-related attributes of a comment.
     * @param $CommentID
     * @return array|bool|stdClass
     */
    public function getComment($CommentID)
    {
        $SQL = Gdn::SQL();

        return $SQL->Select(array('DiscussionID', 'CommentID', 'ParentCommentID', 'TreeLeft', 'TreeRight'))
            ->From('Comment')
            ->Where('CommentID', $CommentID)
            ->Get()
            ->FirstRow();
    }

    /**
     * Replies will always be added to the same part of the tree, i.e. as a last sibling
     * of an existing comment. For example, if replying to comment X, which already has
     * three replies to it, this reply will become the forth child comment of comment X.
     * The ordering replies on the date posted, so if anything starts messing around with
     * those dates, then the ordering of siblings could change.
     * This function opens a gap in the left/right values in the comment tree, then returns
     * the new left, right, and parent ID values as an array.
     * If the left/right values are not contiguous before it starts, then it will rebuild
     * the left/right values for the complete discussion.
     * Note also that the base left/right is in the discussion, so a reply direct to the discussion
     * will open the gap there.
     * The CommentID passed in is the comment we wish to reply to.
     * If $InsertCommentID is set, then that is updated as the comment that is being inserted
     * into the tree..
     * @param $DiscussionID
     * @param $CommentID
     * @param int $InsertCommentID
     * @return array|void
     * @throws Exception
     */
    public function insertPrep($DiscussionID, $CommentID, $InsertCommentID = 0)
    {
        // Get the count of comments in the discussion.
        $CommentCount = $this->commentCount($DiscussionID);

        // Get the current max right value.
        $MaxRight = $this->maxRight($DiscussionID);

        // If the base comment left/right does not match the comment count (excluding the
        // new comment we have just inserted), then rebuild the left/right values for the
        // entire discussion.
        if ($MaxRight != ((2 * $CommentCount) - 2)) {
            // Rebuild. The 'right' value of the right-most comment should be twice the total number
            // of comments, since with this Nested Sets tree model we go up the left
            // and back down the right.
            $this->rebuildLeftRight($DiscussionID);

            // Since we rebuilt the whole tree, there is no point doing the gap-opening stuff
            // that follows.
            // Do not return the left/right values, since they have already been updated.
            return;
        }

        $SQL = Gdn::SQL();

        // Now the main task: opening up a gap in the tree numbering for the new comment.
        // We want to insert as the last child of comment $CommentID.
        // A gap opnly needs to be opened up if this is a reply to an existing comment.
        if ($CommentID > 0) {
            // Get the right value of the new comment parent.
            // This and everything above it will be moved up two places.
            // The left of the new comment will be given the same value as
            // the old right value of the parent comment.
            // We could just rebuild the tree model, but this reduces the number
            // of database rows that need to be updated.

            $InsertComment = $this->getComment($CommentID);

            // If this comment is for a different discussion, then stop now.
            if (empty($InsertComment) || $DiscussionID != $InsertComment->DiscussionID) return;

            $TreeRight = (int)$InsertComment->TreeRight;

            $Update = $SQL->Update('Comment')
                ->Where('DiscussionID', $DiscussionID)
                ->Where('TreeRight >=', $TreeRight)
                ->Set('TreeRight', 'TreeRight + 2', FALSE)
                ->Put();

            $Update = $SQL->Update('Comment')
                ->Where('DiscussionID', $DiscussionID)
                ->Where('TreeLeft >=', $TreeRight)
                ->Set('TreeLeft', 'TreeLeft + 2', FALSE)
                ->Put();

            // Return the left/right/parent information necessary to add to the comment.
            // The new item 'left' replaces the parent 'right', and that shifts the parent 'right' up by two.
            $TreeLeft = $TreeRight;
        } else {
            // There is no parent, so tag the comment on to the end (far right) of the nested set
            // model (left is max right+1 and right is one more again).
            $TreeLeft = $MaxRight + 1;
        }

        if ($InsertCommentID > 0) {
            $Update = $SQL->Update('Comment')
                ->Where('CommentID', $InsertCommentID)
                ->Set('TreeLeft', $TreeLeft)
                ->Set('TreeRight', $TreeLeft + 1)
                ->Put();
        }

        return array(
            'ParentCommentID' => $CommentID,
            'TreeLeft' => $TreeLeft,
            'TreeRight' => $TreeLeft + 1);
    }

    /**
     * Return comment classes for a specified depth.
     * @param $depth
     * @return string
     */
    public function depthClasses($depth) {
        $Prefix = 'ReplyToDepth';
        $Class = $Prefix . '-' . $depth;

        // Add some further classes for blocks of each 5 depth levels, so limits can
        // be set on the way depth is formatted.
        for ($i = 1; $i <= 20; $i += 5) {
            if ($depth >= $i) {
                $Class .= ' ' . $Prefix . '-' . $i . 'plus';
            } else {
                break;
            }
        }
        $cssClass = trim($Class);
        // This is the set of classes that is applied to the comment in the output view.
        return $cssClass;
    }


    /**
     * Count ancestors for a range of comments.
     * Will accept a single comment ID or an array of comment IDs.
     * Returns an array of comment IDs and counts for each.
     * No zero counts will be returned, so an empty array will be returned
     * if none of the supplied comment IDs have ancestor comments.
     * @param array $CommentIDs
     * @return array
     */
    public function CountAncestors($CommentIDs = array()) {
        // Make sure the input is an array.
        if (!is_array($CommentIDs)) {
            $CommentIDs = array($CommentIDs);
        }

        $SQL = Gdn::SQL();

        $Data = $SQL->Select('Roots.CommentID')
            ->Select('Ancs.CommentID', 'count', 'AncestorCount')
            ->From('Comment Roots')
            ->Join('Comment Ancs', 'Ancs.DiscussionID = Roots.DiscussionID'
                . ' AND Ancs.TreeLeft < Roots.TreeLeft'
                . ' AND Ancs.TreeRight > Roots.TreeRight', 'inner');

        if (!empty($CommentIDs)) {
            $Data = $Data->WhereIn('Roots.CommentID', $CommentIDs);
        }

        $Data = $Data->GroupBy('Roots.CommentID')
            ->OrderBy('Roots.CommentID', 'asc')
            ->Get();

        $Counts = array();

        while ($Count = $Data->NextRow()) {
            $Counts[$Count->CommentID] = $Count->AncestorCount;
        }

        return $Counts;
    }

    /**
     * Return a list of ancestor comments IDs for a given comment.
     * The count of ancestors will give the absolue depth of the comment.
     * An empty list will be returned if the comment is hanging directly off the discussion.
     * Note: don't assume the ancestors link to each other contigously. They should do,
     * but if the Nested Tree gets messed up at all - e.g. comments are removed by other
     * plugins without firing events to rebuild the tree - then there may be gaps in the links.
     * The first comment in the list will be the top level, and the last will be the
     * ancestor of the specified comment.
     * @param $CommentID
     * @return array
     */
    public function AncestorComments($CommentID)
    {
        $Comments = array();

        // Get details of the comment we are starting at.
        $Comment = $this->getComment($CommentID);

        // Comment was not found.
        if (empty($Comment)) return $Comments;

        // Comment has no ancestors or the discussion has never been written to with this
        // plugin enabled.
        if (empty($Comment->ParentCommentID)
            || empty($Comment->TreeLeft) || empty($Comment->TreeRight)
        ) return $Comments;

        $SQL = Gdn::SQL();

        // All ancestors will have a TreeLeft and TreeRight that wraps around
        // the current comment's TreeLeft.
        // Select a range of useful columns.

        $Data = $SQL->Select('DiscussionID')
            ->Select('CommentID')->Select('ParentCommentID')
            ->Select('TreeLeft')->Select('TreeRight')
            ->Select('DateInserted')
            ->From('Comment')
            ->Where('DiscussionID', $Comment->DiscussionID)
            ->Where('TreeLeft <', $Comment->TreeLeft)
            ->Where('TreeRight >', $Comment->TreeRight)
            ->OrderBy('TreeLeft', 'asc')
            ->Get();

        while ($Comment = $Data->NextRow()) {
            $Comments[] = $Comment;
        }

        return $Comments;
    }

    public function onDeleteComment($Comment){
        // On deleting a comment, close the left-right gap.
        // If the comment has any children, then they need moving so that they are
        // not orphaned.
        // The default display will still work with gaps not closed and orthaned child
        // comments, but a broken tree becomes less flexible in other things we may
        // wish to do with it. For example, the different between a TreeLeft and TreeRight
        // value for a comment, when divided by two, tells you how any descendants a
        // comment has. However, if those values cannot be trusted to be correct and
        // contigous across the tree, then you need to go count the actual comments.
        $SQL = Gdn::SQL();

        // Left and right will be continuous if there are no children.
        if ($Comment->TreeRight != $Comment->TreeLeft + 1) {
            // Child comments involved - move them first.
            // Move them to the parent of the comment we are about to delete.
            $Update = $SQL->update('Comment')
                ->where('ParentCommentID', $Comment->CommentID)
                ->set('ParentCommentID', $Comment->ParentCommentID)
                ->put();

            // Rebuild the tree, since lots of left/rights could need changing.
            $this->rebuildLeftRight($Comment->DiscussionID);

            // Fetch the comment to be deleted again, just in case (in theory it will not
            // have changed, as the children will be inserted after it).
            $Comment = $this->getComment($Comment->CommentID);

            // If left/right not continguous still, then bail out (something has gone wrong).
            if ($Comment->TreeRight != $Comment->TreeLeft + 1) {
                return;
            }
        }

        // Move all left and right values above the right value of the comment
        // to be deleted, down two places to close up the gap.
        $SQL->update('Comment')
            ->where('DiscussionID', $Comment->DiscussionID)
            ->where('TreeLeft >', $Comment->TreeRight)
            ->set('TreeLeft', 'TreeLeft - 2', FALSE)
            ->put();

        $SQL->update('Comment')
            ->where('DiscussionID', $Comment->DiscussionID)
            ->where('TreeRight >', $Comment->TreeRight)
            ->set('TreeRight', 'TreeRight - 2', FALSE)
            ->put();
    }
}