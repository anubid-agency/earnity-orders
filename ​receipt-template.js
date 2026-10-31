export function getReceiptHtml(p) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light only">
<meta name="supported-color-schemes" content="light only">
<title>Your Earnity order ${p.order_number}</title>
</head>
<body style="margin:0;padding:0;background-color:#f1f4f2;">

<div style="display:none;max-height:0;overflow:hidden;font-size:1px;line-height:1px;color:#f1f4f2;">
Your order is confirmed. Your delivery code is inside. Share it with the seller only when your item arrives.
</div>

<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#f1f4f2" style="background-color:#f1f4f2;">
<tr>
<td align="center" style="padding:20px 10px;">

  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:600px;width:100%;">

    <!-- Header with logo. If the image is blocked, the alt text shows instead. -->
    <tr>
      <td bgcolor="#064e3b" style="background-color:#064e3b;padding:22px 28px;border-radius:12px 12px 0 0;">
        <img src="${p.logo_url}" alt="Earnity" width="140" style="display:block;border:0;outline:none;text-decoration:none;height:auto;max-width:140px;font-family:Georgia,'Times New Roman',serif;font-size:26px;line-height:30px;color:#ffffff;font-weight:bold;">
        <div style="font-family:Arial,Helvetica,sans-serif;font-size:13px;line-height:18px;color:#a7d9c4;padding-top:6px;">Refer, earn, save.</div>
      </td>
    </tr>

    <tr>
      <td bgcolor="#ffffff" style="background-color:#ffffff;padding:28px 28px 8px 28px;">
        <div style="font-family:Arial,Helvetica,sans-serif;font-size:22px;line-height:28px;color:#0f1f19;font-weight:bold;">Your order is confirmed</div>
        <div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:21px;color:#4b5b54;padding-top:6px;">
          Hello ${p.buyer_first_name}, we received your deposit. Order ${p.order_number} &middot; ${p.order_date}
        </div>
      </td>
    </tr>

    <!-- Delivery code -->
    <tr>
      <td bgcolor="#ffffff" style="background-color:#ffffff;padding:16px 28px;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
          <tr>
            <td align="center" bgcolor="#ecf7f1" style="background-color:#ecf7f1;border:2px solid #064e3b;border-radius:10px;padding:20px 12px;">
              <div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:20px;color:#1f3a30;">Your delivery code</div>
              <div style="font-family:'Courier New',Courier,monospace;font-size:38px;line-height:46px;letter-spacing:8px;color:#064e3b;font-weight:bold;padding:6px 0;">${p.delivery_code}</div>
              <div style="font-family:Arial,Helvetica,sans-serif;font-size:13px;line-height:19px;color:#1f3a30;">
                Tell this code to the seller only when your item is in your hands.<br>
                Never share it before delivery, and never send it by message. Earnity staff will never ask for it.
              </div>
            </td>
          </tr>
        </table>
      </td>
    </tr>

    <!-- Order details -->
    <tr>
      <td bgcolor="#ffffff" style="background-color:#ffffff;padding:12px 28px 4px 28px;">
        <div style="font-family:Arial,Helvetica,sans-serif;font-size:16px;line-height:22px;color:#0f1f19;font-weight:bold;padding-bottom:8px;">What you ordered</div>
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:21px;color:#0f1f19;">
          <tr>
            <td style="padding:6px 0;border-bottom:1px solid #e3e9e6;color:#4b5b54;" width="38%" valign="top">Item</td>
            <td style="padding:6px 0;border-bottom:1px solid #e3e9e6;" valign="top">${p.product_name}</td>
          </tr>
          <tr>
            <td style="padding:6px 0;border-bottom:1px solid #e3e9e6;color:#4b5b54;" valign="top">Seller</td>
            <td style="padding:6px 0;border-bottom:1px solid #e3e9e6;" valign="top">${p.seller_name}</td>
          </tr>
          <tr>
            <td style="padding:6px 0;color:#4b5b54;" valign="top">Delivery</td>
            <td style="padding:6px 0;" valign="top">${p.delivery_text} Expected within ${p.delivery_days} days.</td>
          </tr>
        </table>
      </td>
    </tr>

    <!-- Payment -->
    <tr>
      <td bgcolor="#ffffff" style="background-color:#ffffff;padding:16px 28px 4px 28px;">
        <div style="font-family:Arial,Helvetica,sans-serif;font-size:16px;line-height:22px;color:#0f1f19;font-weight:bold;padding-bottom:8px;">Your payment</div>
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:21px;color:#0f1f19;">
          <tr>
            <td style="padding:6px 0;border-bottom:1px solid #e3e9e6;color:#4b5b54;">Item price</td>
            <td align="right" style="padding:6px 0;border-bottom:1px solid #e3e9e6;">UGX ${p.item_price}</td>
          </tr>
          ${p.discount_row}
          <tr>
            <td style="padding:6px 0;border-bottom:1px solid #e3e9e6;color:#4b5b54;">Deposit</td>
            <td align="right" style="padding:6px 0;border-bottom:1px solid #e3e9e6;">UGX ${p.deposit}</td>
          </tr>
          <tr>
            <td style="padding:6px 0;border-bottom:1px solid #e3e9e6;color:#4b5b54;">Payment fee</td>
            <td align="right" style="padding:6px 0;border-bottom:1px solid #e3e9e6;">UGX ${p.payment_fee}</td>
          </tr>
          <tr>
            <td style="padding:8px 0;font-weight:bold;">Paid today</td>
            <td align="right" style="padding:8px 0;font-weight:bold;">UGX ${p.total_paid}</td>
          </tr>
        </table>
        <div style="font-family:Arial,Helvetica,sans-serif;font-size:12px;line-height:18px;color:#6b7a73;padding-top:2px;">The payment fee is charged for processing mobile money and card payments.</div>
      </td>
    </tr>

    <!-- Balance due -->
    <tr>
      <td bgcolor="#ffffff" style="background-color:#ffffff;padding:16px 28px;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
          <tr>
            <td bgcolor="#f1f4f2" style="background-color:#f1f4f2;border-radius:8px;padding:14px 16px;font-family:Arial,Helvetica,sans-serif;">
              <div style="font-size:13px;line-height:19px;color:#4b5b54;">To pay the seller when your item arrives</div>
              <div style="font-size:22px;line-height:28px;color:#0f1f19;font-weight:bold;">UGX ${p.balance_due}</div>
            </td>
          </tr>
        </table>
      </td>
    </tr>

    <!-- Next steps -->
    <tr>
      <td bgcolor="#ffffff" style="background-color:#ffffff;padding:4px 28px 8px 28px;">
        <div style="font-family:Arial,Helvetica,sans-serif;font-size:16px;line-height:22px;color:#0f1f19;font-weight:bold;padding-bottom:6px;">What happens next</div>
        <div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:22px;color:#0f1f19;">
          1. The seller prepares your order and delivers it.<br>
          2. You check the item, then pay the balance to the seller.<br>
          3. You tell the seller your code, and they confirm delivery in their Earnity account.
        </div>
        <div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:22px;color:#0f1f19;padding-top:10px;">
          If the seller does not deliver, you will be refunded.
        </div>
      </td>
    </tr>

    <!-- Button -->
    <tr>
      <td bgcolor="#ffffff" align="center" style="background-color:#ffffff;padding:16px 28px 28px 28px;">
        <table role="presentation" cellpadding="0" cellspacing="0" border="0">
          <tr>
            <td align="center" bgcolor="#064e3b" style="background-color:#064e3b;border-radius:8px;">
              <a href="${p.order_url}" style="display:inline-block;padding:13px 28px;font-family:Arial,Helvetica,sans-serif;font-size:15px;line-height:20px;color:#ffffff;text-decoration:none;font-weight:bold;">View your order</a>
            </td>
          </tr>
        </table>
      </td>
    </tr>

    <!-- Footer with contacts -->
    <tr>
      <td bgcolor="#e6ece9" style="background-color:#e6ece9;padding:18px 28px;border-radius:0 0 12px 12px;">
        <div style="font-family:Arial,Helvetica,sans-serif;font-size:12px;line-height:19px;color:#4b5b54;">
          The seller can see your name, phone and email for this order. Keep this email safe, it holds your delivery code.<br><br>
          Need help: <a href="mailto:support@earnityug.com" style="color:#064e3b;">support@earnityug.com</a><br>
          Report a problem or suspected fraud: <a href="mailto:report@earnityug.com" style="color:#064e3b;">report@earnityug.com</a><br>
          General questions: <a href="mailto:inquiry@earnityug.com" style="color:#064e3b;">inquiry@earnityug.com</a><br>
          More ways to reach us: <a href="https://earnityug.com/contacts.html" style="color:#064e3b;">earnityug.com/contacts.html</a><br><br>
          Earnity &middot; earnityug.com
        </div>
      </td>
    </tr>

  </table>

</td>
</tr>
</table>

</body>
</html>`;
}
