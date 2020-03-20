using System.Windows.Forms;

namespace VanillaRat.Forms
{
    public partial class PasswordViewer : Form
    {
        public PasswordViewer()
        {
            InitializeComponent();
            Update = true;
        }

        public int ConnectionID { get; set; }
        public bool Update { get; set; }

        //On password viewer close
        private void PasswordViewer_FormClosing(object sender, FormClosingEventArgs e)
        {
            Update = false;
        }

        private void lbPasswords_SelectedIndexChanged(object sender, System.EventArgs e)
        {

        }
    }
}