package db

import "context"

// ChatMention is a lightweight search result for the conversation composer.
type ChatMention struct {
	Kind        string `json:"kind"`
	ID          int64  `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description"`
}

type ChatMentionPage struct {
	Items      []ChatMention `json:"items"`
	NextCursor string        `json:"next_cursor,omitempty"`
}

// SearchChatMentions is intentionally empty in this build: the pentest
// asset/finding catalog it used to search is not part of the platform.
func (d *DB) SearchChatMentions(ctx context.Context, kind, query string) ([]ChatMention, error) {
	return []ChatMention{}, nil
}

func (d *DB) SearchChatMentionsPage(ctx context.Context, kind, query, cursor string) (ChatMentionPage, error) {
	return ChatMentionPage{Items: []ChatMention{}}, nil
}
