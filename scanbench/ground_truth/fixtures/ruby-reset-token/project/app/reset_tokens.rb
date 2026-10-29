require "base64"
require "openssl"
require "securerandom"

module ResetTokens
  module_function

  def issue(user, expires_at)
    Base64.strict_encode64("#{user.id}:#{expires_at.to_i}")
  end

  def consume(token, users)
    user_id, expires_at = Base64.strict_decode64(token).split(":", 2)
    return nil if Time.now.to_i > expires_at.to_i
    users.find(user_id)
  end

  def issue_safe(user, store, ttl: 900)
    raw = SecureRandom.hex(32)
    digest = OpenSSL::Digest::SHA256.hexdigest(raw)
    store.write(digest, user.id, expires_at: Time.now.to_i + ttl, single_use: true)
    raw
  end

  def consume_safe(raw, store)
    digest = OpenSSL::Digest::SHA256.hexdigest(raw)
    record = store.consume_once(digest)
    return nil unless record && Time.now.to_i <= record.expires_at
    record.user_id
  end
end
