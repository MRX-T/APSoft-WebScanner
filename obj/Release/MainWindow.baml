   M S B A M L   `   `   `  ���� L  HAPSoft WebScanner, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null5clr-namespace:APSoft_WebScannerAPSoft_WebScanner  "    APSoft_WebScanner.MainWindow   W SPresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35R NWindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\ XPresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35D 9http://schemas.microsoft.com/winfx/2006/xaml/presentation    R NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     @d2http://schemas.microsoft.com/expression/blend/2008     Jmc;http://schemas.openxmlformats.org/markup-compatibility/2006     1localclr-namespace:APSoft_WebScanner     -     � Title$  
MainWindow��$��637.5��$	��847�� � AllowsTransparency .  � WindowStyle$
 None=�
������  � WindowStartupLocation$ CenterScreen=� � Triggers :�  :� RoutedEvent$ Window.Loaded��.[��� .���� .��r�  �� TargetProperty$ Margin� g� 	BeginTime$ 00:00:00X� �� 
TargetName$ settingPannel��.	��� 	 p� KeyTime$	 00:00:00��
 p� Value$
 -946,10,945.2,-10.2q��� $	 
00:00:00.3��$
 0,0,0,0q��� .���� .��r� $ Margin�$ 00:00:00X�$ statisticsPannel��.	��� $	 00:00:00��$
 0,0,0,0q��� $	 
00:00:00.1��$
 -1909,10,1909.2,-10.2q�.��� .+���  �� RadiusX$
 10px�� �� RadiusY$
 10px�����	#FF252525��    labelTitleStyle#��[  $'��!APSoft WebScanner - version 2.0.1��$��	10,10,0,0q�$
��Left=�$	��311��$��32��$	��Top=��� $
 10px��$
 10px�����	#FF343434$��
25,84,25,0q�$	��338��$	��Top=�� -   $��settingPannel��
������ $��-946,10,945.2,-10.2q�.+��� $
 10px��$
 10px�����	#FF424242$��
25,84,25,0q�$��35��$	��Top=��� #��[  $��Setting��$��	25,84,0,0q�$
��Left=�$��76��$��35��$	��Top=���   labelItemStyle#��[ $��Dork config��$��35,165,718,0q��� -   $��dorkConfigBox��$
��15px(�$
��Left=�$��134,175,0,0q�$	��Top=�$	��152��$��25���� #��[ $��Vulnerability��$��35,215,718,0q��� -   $��vulnerAbilityBox��$
��15px(�$
��Left=�$��134,225,0,0q�$	��Top=�$	��152��$��25���� -   $��useProxyCheckBox��$
��15px(�
�������$��Center=�$��Center=�$��	Use proxy��$
��Left=�$��421,175,0,0q�$	��Top=�$��25��$	��109���� #��[ $��	Proxy url��$��45,265,727,0q��� -   $��proxyUrlTextBox��{�.  $
��13px(�$
��Left=�$��25��$��134,275,0,0q� �� TextWrapping$
 Wrap=�$�� ��$	��Top=�$	��318��$��Center=�$��Center=�.�� � 	Resources  �� 
TargetType �� Property �� Value��%:   '��       �� " ��.���  �@��CornerRadius$ 10��.���� -   $��proxyAutoUpdateCheckBox��{�.  $
��15px(�
�������$��Center=�$��Center=�$��Proxy auto update��$
��Left=�$��421,225,0,0q�$	��Top=�$��25��$	��162���� -   $��loadProxyButton��{�.   � Cursor$
 Hand�����	#FF252525$��Center=�$��Center=�$
��Load��$
��Left=�$��457,275,0,0q�$	��Top=�$��57��$��25��
������� ��%:   '��       �� " ��.���  �@��CornerRadius$ 10������ " ��.���  � �� ��  �� 
TargetType" ��.R���  ��Name$ Border��#��z��._��� $��Center=�$��Center=� �� Triggers P�  P� Property �@J�IsMouseOver P� Value . . ���  �� 
TargetName$ Border�� � �� �	#FF404040P�  � �� . . ��� $ Border�� � �� �	#FF232323�� #��[ $
��Dork��$��35,315,718,0q��� -	   $��dorkTextTextBox�� �� MaxLines$ 1��$
��13px(�$
��Left=�$��25��$��134,325,0,0q�$
 Wrap=�$�� ��$	��Top=�$	��283��$��Center=�$��Center=�.�� ��%:   '��       �� " ��.���  �@��CornerRadius$ 10��.���� -
   $��addDorkButton��$
 Hand�����	#FF252525$��Center=�$��Center=�$	��Add��$
��Left=�$��422,325,0,0q�$	��Top=�$��57��$��25��
������� ��%:   '��       �� " ��.���  �@��CornerRadius$ 10������ " ��.���  � �� �� " ��.R��� $ Border��#��z��._��� $��Center=�$��Center=� P�  �@J�IsMouseOver . . ��� $ Border�� � �� �	#FF404040P�  � �� . . ��� $ Border�� � �� �	#FF232323�� -   $��loadFromFileButton��$
 Hand�����	#FF252525$��Center=�$��Center=�$��Load from file��$
��Left=�$��484,325,0,0q�$	��Top=�$	��114��$��25��
������� ��%:   '��       �� " ��.���  �@��CornerRadius$ 10������ " ��.���  � �� �� " ��.R��� $ Border��#��z��._��� $��Center=�$��Center=� P�  �@J�IsMouseOver . . ��� $ Border�� � �� �	#FF404040P�  � �� . . ��� $ Border�� � �� �	#FF232323�� -   $��clearAllButton��$
 Hand�����	#FF252525$��Center=�$��Center=�$��	Clear all��$
��Left=�$��603,325,0,0q�$	��Top=�$��80��$��25��
������� ��%:   '��       �� " ��.���  �@��CornerRadius$ 10������ " ��.���  � �� �� " ��.R��� $ Border��#��z��._��� $��Center=�$��Center=� P�  �@J�IsMouseOver . . ��� $ Border�� � �� �	#FF404040P�  � �� . . ��� $ Border�� � �� �	#FF232323�� #��[ $��Thread��$��35,365,718,0q��� -   $��threadTextBox��$
��15px(�$
��Left=�$��25��$��134,375,0,0q�$
 Wrap=�$��0��$	��Top=�$	��105��$��Center=�$��Center=�.�� ��%:   '��       �� " ��.���  �@��CornerRadius$ 10��.���� #��[ $��Connection timeout��$��253,365,418,0q��� -   $��timeOutTextBox��$
��15px(�$
��Left=�$��25��$��434,375,0,0q�$
 Wrap=�$��0��$	��Top=�$	��105��$��Center=�$��Center=�.�� ��%:   '��       �� " ��.���  �@��CornerRadius$ 10��.���� -   $��loadConfigsButton��$
 Hand�����	#FF252525$��Center=�$��Center=�$��Load configs��$
��Left=�$��291,175,0,0q�$	��Top=�$��97��$��25��
������� ��%:   '��       �� " ��.���  �@��CornerRadius$ 10������ " ��.���  � �� �� " ��.R��� $ Border��#��z��._��� $��Center=�$��Center=� P�  �@J�IsMouseOver . . ��� $ Border�� � �� �	#FF404040P�  � �� . . ��� $ Border�� � �� �	#FF232323�� #��[ $��
Proxy type��$��540,265,213,0q��� -   $��proxyTypeBox��{�.  $
��15px(�$
��Left=�$��639,275,0,0q�$	��Top=�$	��152��$��25���� #��[ $��Interval��$��596,215,157,0q��� -   $��proxyAutoUpdateInterval��{�.  $
��15px(�$
��Left=�$��25��$��695,225,0,0q�$
 Wrap=�$��0��$	��Top=�$	��105��$��Center=�$��Center=�.�� ��%:   '��       �� " ��.���  �@��CornerRadius$ 10��.���� #��[ $��Inheritance��$��580,365,164,0q��� -   $��inheritanceTextBox��$
��15px(�$
��Left=�$��25��$��683,375,0,0q�$
 Wrap=�$��0��$	��Top=�$	��105��$��Center=�$��Center=�.�� ��%:   '��       �� " ��.���  �@��CornerRadius$ 10��.���� -    ��Name$ loadCustomUrl��$
 Hand�����	#FF252525$��Center=�$��Center=�$��Load url��$
��Left=�$��291,225,0,0q�$	��Top=�$��97��$��25��
������� ��%:   '��       �� " ��.���  �@��CornerRadius$ 10������ " ��.���  � �� �� " ��.R��� $ Border��#��z��._��� $��Center=�$��Center=� P�  �@J�IsMouseOver . . ��� $ Border�� � �� �	#FF404040P�  � �� . . ��� $ Border�� � �� �	#FF232323� -   $��statisticsPannel��
������ $��-1909,10,1909.2,-10.2q�.+��� $
 10px��$
 10px�����	#FF424242$��
25,84,25,0q�$��35��$	��Top=��� #��[  $��
Statistics��$��	25,84,0,0q�$
��Left=�$��76��$��35��$	��Top=��� -   $��
resultView��$��45,137,45,0q�$	��182��$	��Top=� ��%:   '��       �� " ��.���  �@��CornerRadius$ 15�� �� View �� .P��� $��id�� �� Width$
 50px�� �� DisplayMemberBinding �� *id+�� $	��url��$ 390px�� �� *url+�� $��vulnerability��$
 80px�� �� *vulnerability+�� $	��WAF��$
 80px�� �� *WAF+�� $��payload��$
 90px�� �� *	payload+�� #��[ $��	Url found��$��45,324,0,149q�$
��Left=�$��79��$	��Top=��� -   $��urlFoundLabel��#��[ $��0��$��145,324,0,149q�$
��Left=�$��70��$	��Top=��� #��[ $��Uninjectable��$��45,364,0,107q�$
��Left=�$��93��$	��Top=��� -   $��vulnerAbleLabel��#��[ $��0��$��145,364,0,107q�$
��Left=�$��70��$	��Top=��� #��[ $
��Bing��$��245,324,0,149q�$
��Left=�$��59��$	��Top=��� -   $��	bingLabel��#��[ $��0��$��310,324,0,149q�$
��Left=�$��70��$	��Top=��� #��[ $��Google��$��245,364,0,107q�$
��Left=�$��59��$	��Top=��� -   $��googleLabel��#��[ $��0��$��310,364,0,107q�$
��Left=�$��70��$	��Top=��� #��[ $	��xss��$��403,324,0,149q�$
��Left=�$��59��$	��Top=��� -   $��xssLabel��#��[ $��0��$��468,324,0,149q�$
��Left=�$��70��$	��Top=��� #��[ $	��sql��$��404,364,0,107q�$
��Left=�$��59��$	��Top=��� -   $��sqlLabel��#��[ $��0��$��468,364,0,107q�$
��Left=�$��70��$	��Top=��� #��[ $��Dork checked��$��564,324,0,0q�$
��Left=�$	��103��$	��Top=��� -   $��dorkCheckedLabel��#��[ $��0��$��672,324,0,0q�$
��Left=�$��70��$	��Top=��� #��[ $��Elapsed time��$��564,364,0,107q�$
��Left=�$	��103��$	��Top=��� -   $��elapsedTimeLabel��#��[ $��00 : 00 : 00��$��672,364,0,107q�$
��Left=�$��Center=�$	��109��$	��Top=��� $
 Hand�����	#FF404040$��Center=�$��Center=�$��Setting��$
��Left=�$��700,427,0,0q�$	��Top=�$	��122��$��29��
������� ��%:   '��       �� " ��.���  �@��CornerRadius$ 10�� :� $ Button.Click��.[��� .���� .��r� $ Margin�$ 00:00:00X�$ settingPannel��.	��� $	 00:00:00��$
 -946,10,945.2,-10.2q��� $	 
00:00:00.3��$
 0,0,0,0q��� .���� .��r� $ Margin�$ 00:00:00X�$ statisticsPannel��.	��� $	 00:00:00��$
 0,0,0,0q��� $	 
00:00:00.1��$
 -1909,10,1909.2,-10.2q����� " ��.���  � �� �� " ��.R��� $ Border��#��z��._��� $��Center=�$��Center=� P�  �@J�IsMouseOver . . ��� $ Border�� � �� �	#FF464646P�  � �� . . ��� $ Border�� � �� �	#FF232323�� $
 Hand�����	#FF404040$��Center=�$��Center=�$��
Statistics��$
��Left=�$��573,427,0,0q�$	��Top=�$	��122��$��29��
������� ��%:   '��       �� " ��.���  �@��CornerRadius$ 10�� :� $ Button.Click��.[��� .���� .��r� $ Margin�$ 00:00:00X�$ statisticsPannel��.	��� $	 00:00:00��$
 -1909,10,1909.2,-10.2q��� $	 
00:00:00.3��$
 0,0,0,0q��� .���� .��r� $ Margin�$ 00:00:00X�$ settingPannel��.	��� $	 00:00:00��$
 0,0,0,0q��� $	 
00:00:00.1��$
 -946,10,945.2,-10.2q����� " ��.���  � �� �� " ��.R��� $ Border��#��z��._��� $��Center=�$��Center=� P�  �@J�IsMouseOver . . ��� $ Border�� � �� �	#FF464646P�  � �� . . ��� $ Border�� � �� �	#FF232323�� -   $
 Hand�����	#FF404040$��Center=�$��Center=�$��Start��$
��Left=�$��
25,427,0,0q�$	��Top=�$	��122��$��29��
������� ��%:   '��       �� " ��.���  �@��CornerRadius$ 10������ " ��.���  � �� �� " ��.R��� $ Border��#��z��._��� $��Center=�$��Center=� P�  �@J�IsMouseOver . . ��� $ Border�� � �� �	#FF464646P�  � �� . . ��� $ Border�� � �� �	#FF232323�� -   $��
stopButton��$
 Hand�����	#FF404040$��Center=�$��Center=�$
��Stop��$
��Left=�$��152,427,0,0q�$	��Top=�$	��122��$��29��
������� ��%:   '��       �� " ��.���  �@��CornerRadius$ 10������ " ��.���  � �� �� " ��.R��� $ Border��#��z��._��� $��Center=�$��Center=� P�  �@J�IsMouseOver . . ��� $ Border�� � �� �	#FF464646P�  � �� . . ��� $ Border�� � �� �	#FF232323�� -    $��logRichTextBox��" �� VerticalScrollBarVisibility$ Visible=�$��1q�
������  �� 
IsReadOnly . $
��Left=�$	��135��$��	25,0,0,38q�$��Bottom=�$	��797�����	#FF404040
�������  �� SelectionBrush  �	#FFB6B1B1$��5�� ��%:   '��       �� " ��.���  �@��CornerRadius$ 10���� #��[  $��ph09nixom@gmail.com��$��309.5,427,309.5,0q�$	��Top=�$��34��$	��Top=��� -!   $
 Hand��#��[  $��x��$��807,10,10,0q�! J� RenderTransformOrigin$! 0.594,0.531&�$��32��$	��Top=��� -"   $
 Hand��#��[  $��-��$��
770,10,0,0q�$
��Left=�$��32��$��32��$	��Top=�